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

An endpoint counts as tamper protected only when tamperProtectionEnabled is literally true.
An endpoint that reports tamperProtectionSupported false cannot be tamper protected, so it
counts as not protected and is named separately in the reasons.

Verdict:
  True   at least one active endpoint, and every active endpoint reports it on.
  False  at least one active endpoint reports it off (or unsupported).
  None   (Not evaluated) the response is missing, an error, has no endpoints, or no active
         endpoint carries the field; also when some carry it (all on) and others do not,
         because "every endpoint" cannot then be shown.
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

        active, stale = active_endpoints(items)
        on = []
        off = []
        unsupported = []
        unknown = []
        for endpoint in active:
            enabled = flag(endpoint.get("tamperProtectionEnabled"))
            supported = flag(endpoint.get("tamperProtectionSupported"))
            if enabled is True:
                on.append(endpoint)
            elif supported is False:
                unsupported.append(endpoint)
            elif enabled is False:
                off.append(endpoint)
            else:
                unknown.append(endpoint)

        judged = len(on) + len(off) + len(unsupported)
        pct = round((len(on) / judged) * 100) if judged else 0
        summary = {
            "activeEndpoints": len(active),
            "tamperProtectedEndpoints": len(on),
            "tamperProtectionOffEndpoints": len(off),
            "tamperProtectionUnsupportedEndpoints": len(unsupported),
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

        if off or unsupported:
            fail_reasons = []
            recommendations = []
            if off:
                fail_reasons.append(str(len(off)) + " of " + str(len(active)) + " active endpoint(s) report tamper protection off")
                recommendations.append("Turn on tamper protection in Sophos Central for: " + ", ".join(summary["endpointsWithTamperProtectionOff"]))
            if unsupported:
                fail_reasons.append(str(len(unsupported)) + " of " + str(len(active)) + " active endpoint(s) report that they do not support tamper protection")
                recommendations.append("Update or replace the Sophos agent on endpoints that cannot run tamper protection: " + ", ".join(summary["endpointsWithoutTamperSupport"]))
            if unknown:
                fail_reasons.append(str(len(unknown)) + " active endpoint(s) did not report tamper protection")
            return create_response(result={criteriaKey: False, **summary}, validation=validation,
                                   fail_reasons=fail_reasons, recommendations=recommendations,
                                   input_summary={criteriaKey: False, **summary})

        if unknown:
            return not_evaluated(
                str(len(unknown)) + " of " + str(len(active)) + " active endpoint(s) did not report tamperProtectionEnabled, so tamper protection on every endpoint cannot be shown",
                validation, summary,
                "Read the endpoints list with view=full so every endpoint carries tamperProtectionEnabled")

        return create_response(result={criteriaKey: True, **summary}, validation=validation,
                               pass_reasons=["Tamper protection is on for all " + str(len(on)) + " active endpoint(s)"],
                               input_summary={criteriaKey: True, **summary})
    except Exception as e:
        reason = "Transformation error: " + str(e)
        return create_response(result={criteriaKey: None},
                               validation={"status": "error", "errors": [], "warnings": []},
                               api_errors=[reason], transformation_errors=[str(e)],
                               fail_reasons=[reason])
