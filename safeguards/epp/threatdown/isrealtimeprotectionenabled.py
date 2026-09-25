"""
Transformation: isRealTimeProtectionEnabled
Vendor: ThreatDown (Malwarebytes Nebula)  |  Category: Endpoint Security
Method: getEndpoints (POST /nebula/v1/endpoints, the endpoint search; cursor-paginated on "endpoints")

Evidence: each endpoint's `protection_status` (documented in the Nebula OpenAPI response for
POST /nebula/v1/endpoints). ThreatDown's support article "Endpoint protection statuses in
Nebula" (updated 2026-07-16) defines the values:
  - Protected         the Endpoint Protection plugin is installed and running
  - Unprotected       the EP plugin may not be installed (or Mac web protection extension blocked)
  - Scan Only         no EP subscription, OR the endpoint's policy has Malware protection
                      (real-time protection) disabled, OR macOS Full Disk Access is missing
  - Pending           the machine has not uploaded agent information
  - Mobile Protection iOS, Android and Chrome OS devices
  - Unknown           the EP plugin is corrupted and not communicating
The field is reported for every platform (Windows, macOS, Linux), so a platform-specific
field cannot fail one OS for lack of data.

Rule: an endpoint is judged when it is not deleted and was seen within 7 days of the newest
`machine.last_day_seen` in the response (an endpoint with no date is judged). Mobile devices
("Mobile Protection") are counted but not judged: that status designates a device class, not
a real-time scanning state. The value is true when at least one endpoint is judged and every
judged endpoint is "Protected". Values are compared case- and separator-insensitively
("Scan Only", "scan_only" and "scanonly" are the same status).

Proves: the ThreatDown real-time Endpoint Protection engine is installed and running on every
active desktop/server endpoint in the Nebula account.
Does not prove: each individual policy toggle (web, exploit, ransomware), or anything about
devices ThreatDown does not manage.
"""
import json
from datetime import datetime, timedelta


ACTIVE_WINDOW_DAYS = 7
PROTECTED = "protected"
MOBILE = "mobileprotection"


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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isRealTimeProtectionEnabled", "vendor": "ThreatDown", "category": "Endpoint Security"}
        }
    }


def api_error_message(data):
    if isinstance(data, dict) and (data.get("error") is True or str(data.get("error")).lower() == "true"):
        return str(data.get("errorMessage") or data.get("message") or "ThreatDown API returned an error")
    return None


def endpoint_list(data):
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        endpoints = data.get("endpoints")
        if isinstance(endpoints, list):
            return endpoints
    return None


def normalise(value):
    return "".join(ch for ch in str(value or "").lower() if ch.isalnum())


def parse_day(value):
    try:
        # strptime imports _strptime, which the Token-Service sandbox refuses.
        return datetime.fromisoformat(str(value)[:10])
    except Exception:
        return None


def endpoint_name(endpoint):
    agent = endpoint.get("agent") or {}
    return endpoint.get("display_name") or agent.get("host_name") or (endpoint.get("machine") or {}).get("id") or "unknown"


def judged_endpoints(endpoints):
    """Return (judged, mobile_count, stale_count, deleted_count)."""
    live = []
    deleted = 0
    for endpoint in endpoints:
        if not isinstance(endpoint, dict):
            continue
        if (endpoint.get("machine") or {}).get("is_deleted") is True:
            deleted = deleted + 1
            continue
        live.append(endpoint)
    seen = [parse_day((e.get("machine") or {}).get("last_day_seen")) for e in live]
    known = [s for s in seen if s is not None]
    cutoff = max(known) - timedelta(days=ACTIVE_WINDOW_DAYS) if known else None
    judged = []
    mobile = 0
    stale = 0
    for endpoint, when in zip(live, seen):
        if cutoff is not None and when is not None and when < cutoff:
            stale = stale + 1
        elif normalise(endpoint.get("protection_status")) == MOBILE:
            mobile = mobile + 1
        else:
            judged.append(endpoint)
    return judged, mobile, stale, deleted


def transform(input):
    criteriaKey = "isRealTimeProtectionEnabled"
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
        endpoints = endpoint_list(data)
        if error or endpoints is None:
            reason = error or "Endpoints response not recognised - no endpoints list present"
            return create_response(result={criteriaKey: False}, validation=validation,
                                   api_errors=[reason], fail_reasons=[reason],
                                   recommendations=["Verify the ThreatDown endpoint search (POST /nebula/v1/endpoints) is reachable with the accountid header"])

        judged, mobile, stale, deleted = judged_endpoints(endpoints)
        statuses = {}
        not_protected = []
        for endpoint in judged:
            status = str(endpoint.get("protection_status") or "missing")
            statuses[status] = statuses.get(status, 0) + 1
            if normalise(status) != PROTECTED:
                not_protected.append(endpoint_name(endpoint) + " (" + status + ")")
        value = len(judged) > 0 and len(not_protected) == 0

        summary = {
            "judgedEndpoints": len(judged),
            "protectedEndpoints": len(judged) - len(not_protected),
            "protectionStatusCounts": statuses,
            "endpointsNotProtected": not_protected[:20],
            "mobileEndpointsNotJudged": mobile,
            "staleEndpointsExcluded": stale,
            "deletedEndpointsExcluded": deleted,
        }
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if not judged:
            fail_reasons.append("No active ThreatDown-managed desktop or server endpoint in the response")
            recommendations.append("Deploy the ThreatDown endpoint agent, then re-run the evaluation")
        elif value:
            pass_reasons.append(f"All {len(judged)} active endpoint(s) report protection status Protected (real-time Endpoint Protection running)")
        else:
            fail_reasons.append(f"{len(not_protected)} of {len(judged)} active endpoint(s) are not in Protected status")
            recommendations.append("Enable Malware protection in the endpoint's policy (Scan Only), reinstall the agent (Unprotected/Unknown), or grant macOS Full Disk Access: " + ", ".join(not_protected[:20]))

        return create_response(result={criteriaKey: value, **summary}, validation=validation,
                               pass_reasons=pass_reasons, fail_reasons=fail_reasons,
                               recommendations=recommendations, input_summary={criteriaKey: value, **summary})
    except Exception as e:
        return create_response(result={criteriaKey: False},
                               validation={"status": "error", "errors": [], "warnings": []},
                               transformation_errors=[str(e)], fail_reasons=[f"Transformation error: {str(e)}"])
