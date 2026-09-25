"""
Transformation: isPatchManagementEnabled
Vendor: Sophos Central (Intercept X / Endpoint)  |  Category: Endpoint Security
Method: getEndpointsFullView (GET /endpoint/v1/endpoints?view=full)

Evidence: the per-endpoint field lastOsUpdateAt, documented at
developer.sophos.com/reference/endpoint-v1/endpoints/list-endpoints-by-tenant-id/ as
"Date and time (UTC) when the endpoint last applied an operating system update".
Only the 'full' view returns it; the default 'summary' view (what getEndpoints reads)
does not. Measured 2026-09-24: 0 of 174 endpoints in two live summary-view payloads
carried the field.

An active endpoint (seen within 7 days of the newest lastSeenAt in the response)
counts as patched when it applied an operating system update no more than 45 days
before that newest lastSeenAt. 45 days covers one monthly vendor patch cycle plus
the delay before a reboot. The newest lastSeenAt is the clock, as in the other Sophos
files, so the verdict does not depend on when the evaluation runs.

Verdict: true when at least one active endpoint reports an OS update date and every
endpoint that reports one applied it within 45 days. Sophos reports lastOsUpdateAt for
Windows only: measured 2026-09-25 on a live full-view payload, 12 of 13 active
endpoints without it were macOS or Linux. A Windows endpoint with no date still counts
as not proven; a macOS or Linux endpoint with no date is excluded and listed, not
failed, since Sophos cannot report it.

What this proves: operating system updates are being applied on every active
Sophos-managed endpoint (servers included). What it does not prove: that every
available patch was applied (a recent partial update still counts), third-party
application patching, or anything about devices Sophos does not manage.
"""
import json
from datetime import datetime, timedelta


ACTIVE_WINDOW_DAYS = 7
MAX_OS_UPDATE_AGE_DAYS = 45


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), (dict, list)):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped or not isinstance(data, dict):
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None,
                    api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isPatchManagementEnabled", "vendor": "Sophos", "category": "Endpoint Security"}
        }
    }


def endpoint_items(data):
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        items = data.get("items")
        if isinstance(items, list):
            return items
    return None


def api_error_message(data):
    if isinstance(data, dict) and (data.get("error") is True or str(data.get("error")).lower() == "true"):
        return str(data.get("errorMessage") or data.get("message") or "Sophos API returned an error")
    if isinstance(data, dict) and str(data.get("status", "")).lower() == "error":
        return str(data.get("message") or "Sophos API returned an error")
    return None


def parse_time(value):
    if value is None or value == "":
        return None
    try:
        # strptime imports _strptime, which the Token-Service sandbox refuses.
        return datetime.fromisoformat(str(value)[:19])
    except Exception:
        return None


def active_endpoints(items):
    """Split endpoints into (active, stale_count) using the newest lastSeenAt as the clock."""
    endpoints = [e for e in items if isinstance(e, dict)]
    seen = [parse_time(e.get("lastSeenAt")) for e in endpoints]
    known = [s for s in seen if s is not None]
    if not known:
        return endpoints, 0, None
    newest = max(known)
    cutoff = newest - timedelta(days=ACTIVE_WINDOW_DAYS)
    active = []
    stale = 0
    for endpoint, when in zip(endpoints, seen):
        if when is not None and when < cutoff:
            stale = stale + 1
        else:
            active.append(endpoint)
    return active, stale, newest


def transform(input):
    criteriaKey = "isPatchManagementEnabled"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(result={criteriaKey: False}, validation=validation,
                                   fail_reasons=["Input validation failed"])

        error = api_error_message(data)
        items = endpoint_items(data)
        if error or items is None:
            reason = error or "Endpoints response not recognised - no items list present"
            return create_response(result={criteriaKey: False}, validation=validation,
                                   api_errors=[reason], fail_reasons=[reason],
                                   recommendations=["Verify the Sophos endpoints API (/endpoint/v1/endpoints?view=full) is reachable for this tenant"])

        active, stale, newest = active_endpoints(items)
        patched = []
        outdated = []
        missing = []
        unreported = []
        for endpoint in active:
            host = str(endpoint.get("hostname") or endpoint.get("id") or "unknown")
            updated = parse_time(endpoint.get("lastOsUpdateAt"))
            platform = str((endpoint.get("os") or {}).get("platform") or "").lower()
            if updated is None and platform in ("macos", "linux"):
                unreported.append(host + " (" + platform + ")")
            elif updated is None or newest is None:
                missing.append(host)
            elif newest - updated > timedelta(days=MAX_OS_UPDATE_AGE_DAYS):
                outdated.append(host + " (" + str(endpoint.get("lastOsUpdateAt"))[:10] + ")")
            else:
                patched.append(host)

        eligible = len(active) - len(unreported)
        value = eligible > 0 and len(patched) == eligible
        summary = {
            "activeEndpoints": len(active),
            "endpointsPatchedWithinWindow": len(patched),
            "maxOsUpdateAgeDays": MAX_OS_UPDATE_AGE_DAYS,
            "endpointsWithOldOsUpdate": outdated[:20],
            "endpointsWithoutOsUpdateDate": missing[:20],
            "nonWindowsEndpointsExcluded": unreported[:20],
            "staleEndpointsExcluded": stale,
        }

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if eligible <= 0:
            fail_reasons.append("No active endpoint reports an OS update date, so OS patching could not be confirmed")
            recommendations.append("Check that the Sophos Central credential can read endpoints (Windows endpoints report lastOsUpdateAt)")
        elif value:
            pass_reasons.append(f"All {eligible} active endpoint(s) that report an OS update date applied one within {MAX_OS_UPDATE_AGE_DAYS} days")
            if unreported:
                pass_reasons.append(f"{len(unreported)} macOS/Linux endpoint(s) excluded: Sophos does not report their OS update date")
        else:
            if outdated:
                fail_reasons.append(f"{len(outdated)} of {len(active)} active endpoint(s) have not applied an OS update in over {MAX_OS_UPDATE_AGE_DAYS} days")
                recommendations.append("Apply operating system updates on: " + ", ".join(outdated[:20]))
            if missing:
                fail_reasons.append(f"{len(missing)} of {len(active)} active endpoint(s) report no OS update date to Sophos")
                recommendations.append("Confirm OS update reporting for: " + ", ".join(missing[:20]))

        return create_response(result={criteriaKey: value, **summary}, validation=validation,
                               pass_reasons=pass_reasons, fail_reasons=fail_reasons,
                               recommendations=recommendations, input_summary={criteriaKey: value, **summary})
    except Exception as e:
        return create_response(result={criteriaKey: False},
                               validation={"status": "error", "errors": [], "warnings": []},
                               transformation_errors=[str(e)], fail_reasons=[f"Transformation error: {str(e)}"])
