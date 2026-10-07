"""
Transformation: isTamperProtectionEnabled
Vendor: Sophos Central (Intercept X / Endpoint, EDR and MDR)  |  Category: Endpoint Security
Method: getEndpoints (GET /endpoint/v1/endpoints)

Sophos reports tamper protection per endpoint on the endpoints list:
  tamperProtectionEnabled    "Whether Tamper Protection is turned on."
  tamperProtectionSupported  "Whether the endpoint supports Tamper Protection."
(developer.sophos.com, endpoint-v1, list endpoints). Sophos documents both under the full
view; measured on live tenants on 2026-10-06 the default view returns them on every
endpoint too. A response that does not carry the field is not evidence and reads Not
evaluated, never pass or fail.

Only endpoints seen within 15 days of the newest lastSeenAt in the response are judged,
because the flag is only as current as the endpoint's last check-in. Stale endpoints are
counted and returned, not silently dropped.

Support is read BEFORE the enabled flag. Endpoints that report tamperProtectionSupported
false (for example Linux servers) can still report tamperProtectionEnabled true, which is
not protection. They are EXCLUDED from the verdict and NAMED in the evidence: a "no" for
them could never be fixed in Sophos, and an L4 "no" must be fixable in the tool.

An endpoint counts as tamper protected only when it is supported (or does not say) and
tamperProtectionEnabled is literally true.

Verdict:
  True   at least one active supported endpoint, and every one of them reports it on.
  False  at least one active supported endpoint reports it off.
  None   (Not evaluated) the response is missing, an error, shows unread pages
         (pages.nextKey still set, or pages.truncated true), has no endpoints, no active
         endpoint, every active endpoint is unsupported, or no active endpoint carries the
         field; also when some carry it (all on) and others do not, because "every
         endpoint" cannot then be shown.
The requirement token compares isEquals true.
"""
import json
from datetime import datetime, timedelta


ACTIVE_WINDOW_DAYS = 15
NAME_LIMIT = 20


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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isTamperProtectionEnabled", "vendor": "Sophos", "category": "Endpoint Security"}
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


def unread_pages(data, item_count):
    """Why the list may be incomplete, or None when it is shown complete. The platform follows
    pages.nextKey and merges items; a nextKey still set means pages were left unread."""
    if not isinstance(data, dict):
        return None
    pages = data.get("pages")
    if not isinstance(pages, dict):
        return None
    truncated = pages.get("truncated")
    if truncated is True or (isinstance(truncated, str) and truncated.strip().lower() == "true"):
        return "the platform marked the endpoints list truncated (pages.truncated is true)"
    if pages.get("nextKey"):
        return "the endpoints list has further pages (pages.nextKey is set) that were not read"
    total = pages.get("total")
    size = pages.get("size")
    if isinstance(total, int) and not isinstance(total, bool) and total > 1 and \
            isinstance(size, int) and not isinstance(size, bool) and item_count <= size:
        return "the endpoints list reports " + str(total) + " pages but only one page of endpoints is present"
    if "nextKey" not in pages and isinstance(size, int) and not isinstance(size, bool) and size > 0 and item_count >= size:
        return "the first page of endpoints is full and the response does not show whether more pages exist"
    return None


def api_error_message(data):
    if isinstance(data, dict) and (data.get("error") is True or str(data.get("error")).lower() == "true"):
        return str(data.get("errorMessage") or data.get("message") or "Sophos API returned an error")
    return None


def parse_seen(value):
    try:
        # strptime imports _strptime, which the Token-Service sandbox refuses.
        return datetime.fromisoformat(str(value)[:19])
    except Exception:
        return None


def active_endpoints(items):
    """Split endpoints into (active, stale_count) using the newest lastSeenAt as the clock."""
    endpoints = [e for e in items if isinstance(e, dict)]
    seen = [parse_seen(e.get("lastSeenAt")) for e in endpoints]
    known = [s for s in seen if s is not None]
    if not known:
        return endpoints, 0
    cutoff = max(known) - timedelta(days=ACTIVE_WINDOW_DAYS)
    wall_cutoff = datetime.utcnow() - timedelta(days=ACTIVE_WINDOW_DAYS)
    if max(known) < wall_cutoff:
        # Dark fleet: the newest check-in is itself older than the window, so every endpoint is stale.
        cutoff = wall_cutoff
    active = []
    stale = 0
    for endpoint, when in zip(endpoints, seen):
        if when is not None and when < cutoff:
            stale = stale + 1
        else:
            active.append(endpoint)
    return active, stale


def flag(value):
    """Read a Sophos boolean strictly: True, False, or None when absent or unrecognised."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in ("true", "false"):
        # Stored replays carry every leaf as a string.
        return value.strip().lower() == "true"
    return None


def label(endpoint):
    return str(endpoint.get("hostname") or endpoint.get("id") or "unknown")


def not_evaluated(reason, validation, input_summary=None, recommendation=None):
    criteriaKey = "isTamperProtectionEnabled"
    return create_response(
        result={criteriaKey: None, **(input_summary or {})},
        validation=validation,
        api_errors=[reason],
        fail_reasons=[reason],
        recommendations=[recommendation or "Verify the Sophos endpoints API (/endpoint/v1/endpoints) is reachable for this tenant"],
        input_summary={criteriaKey: None, **(input_summary or {})},
    )


def transform(input):
    criteriaKey = "isTamperProtectionEnabled"
    validation = {"status": "unknown", "errors": [], "warnings": []}
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return not_evaluated("Input validation failed", validation)

        error = api_error_message(data)
        items = endpoint_items(data)
        if error or items is None:
            return not_evaluated(error or "Endpoints response not recognised - no items list present", validation)

        partial = unread_pages(data, len(items))
        if partial:
            return not_evaluated("Not every endpoint was read: " + partial, validation,
                                 recommendation="Read every page of /endpoint/v1/endpoints before judging tamper protection")

        active, stale = active_endpoints(items)
        on = []
        off = []
        unsupported = []
        unknown = []
        for endpoint in active:
            enabled = flag(endpoint.get("tamperProtectionEnabled"))
            supported = flag(endpoint.get("tamperProtectionSupported"))
            if supported is False:
                unsupported.append(endpoint)
            elif enabled is True:
                on.append(endpoint)
            elif enabled is False:
                off.append(endpoint)
            else:
                unknown.append(endpoint)

        judged = len(on) + len(off)
        pct = round((len(on) / judged) * 100) if judged else 0
        summary = {
            "activeEndpoints": len(active),
            "judgedEndpoints": len(active) - len(unsupported),
            "tamperProtectedEndpoints": len(on),
            "tamperProtectionOffEndpoints": len(off),
            "unsupportedEndpointsExcluded": len(unsupported),
            "endpointsWithoutTamperData": len(unknown),
            "tamperProtectedPercentage": pct,
            "endpointsWithTamperProtectionOff": [label(e) for e in off][:NAME_LIMIT],
            "endpointsWithoutTamperSupport": [label(e) for e in unsupported][:NAME_LIMIT],
            "staleEndpointsExcluded": stale,
        }

        if not active:
            return not_evaluated(
                "No active endpoint in the response (" + str(stale) + " stale excluded): there is nothing to judge",
                validation, summary,
                "Confirm Sophos endpoints are checking in to Sophos Central")

        findings = []
        if unsupported:
            findings.append(str(len(unsupported)) + " active endpoint(s) report that Sophos does not support tamper protection on them and are excluded: "
                            + ", ".join(summary["endpointsWithoutTamperSupport"]))

        if len(unsupported) == len(active):
            return create_response(
                result={criteriaKey: None, **summary}, validation=validation,
                api_errors=["Every active endpoint reports that tamper protection is not supported, so there is nothing to judge"],
                fail_reasons=["Every active endpoint reports that tamper protection is not supported, so there is nothing to judge"],
                additional_findings=findings,
                input_summary={criteriaKey: None, **summary})

        judged_count = len(active) - len(unsupported)
        if off:
            fail_reasons = [str(len(off)) + " of " + str(judged_count) + " active supported endpoint(s) report tamper protection off"]
            recommendations = ["Turn on tamper protection in Sophos Central for: " + ", ".join(summary["endpointsWithTamperProtectionOff"])]
            if unknown:
                fail_reasons.append(str(len(unknown)) + " active endpoint(s) did not report tamper protection")
            return create_response(result={criteriaKey: False, **summary}, validation=validation,
                                   fail_reasons=fail_reasons, recommendations=recommendations,
                                   additional_findings=findings,
                                   input_summary={criteriaKey: False, **summary})

        if unknown:
            return not_evaluated(
                str(len(unknown)) + " of " + str(judged_count) + " active supported endpoint(s) did not report tamperProtectionEnabled, so tamper protection on every endpoint cannot be shown",
                validation, summary,
                "Read the endpoints list with view=full so every endpoint carries tamperProtectionEnabled")

        return create_response(result={criteriaKey: True, **summary}, validation=validation,
                               pass_reasons=["Tamper protection is on for all " + str(len(on)) + " active supported endpoint(s)"],
                               additional_findings=findings,
                               input_summary={criteriaKey: True, **summary})
    except Exception as e:
        reason = "Transformation error: " + str(e)
        return create_response(result={criteriaKey: None},
                               validation={"status": "error", "errors": [], "warnings": []},
                               api_errors=[reason], transformation_errors=[str(e)],
                               fail_reasons=[reason])
