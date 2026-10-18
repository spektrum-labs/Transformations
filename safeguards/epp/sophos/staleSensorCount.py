"""
Transformation: staleSensorCount
Vendor: Sophos Central (Intercept X / Endpoint)  |  Category: Endpoint Security
Method: getEndpoints (GET /endpoint/v1/endpoints)

Value: the number of computers and servers Sophos Central lists that have not been seen
within 15 days of the newest lastSeenAt in the response (endpoint rules 2026-09-29). Those
endpoints are left out of every other Sophos endpoint check, so this count is where they
surface: a console full of decommissioned or dark machines is a hygiene finding, not a pass.
The pass bar lives in the requirement (e.g. equals 0). A body with no endpoint list, or an
API error, is not evaluated (no value).
"""
import json
from datetime import datetime, timedelta


ACTIVE_WINDOW_DAYS = 15

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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "staleSensorCount", "vendor": "Sophos", "category": "Endpoint Security"}
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




def transform(input):
    criteriaKey = "staleSensorCount"
    if isinstance(input, (str, bytes)):
        try:
            input = json.loads(input)
        except Exception:
            input = {}
    data, validation = extract_input(input)
    error = api_error_message(data)
    items = endpoint_items(data)
    if error or items is None:
        reason = error or "The response held no Sophos endpoint list, so stale endpoints could not be counted."
        return create_response(result={criteriaKey: None}, validation=validation,
                               api_errors=[reason], fail_reasons=[reason])
    machines = [e for e in items if isinstance(e, dict) and e.get("type") in ("computer", "server")]
    active, stale = active_endpoints(machines)
    pass_reasons = []
    fail_reasons = []
    recommendations = []
    if stale:
        fail_reasons.append(
            f"{stale} of {len(machines)} Sophos computers and servers have not been seen within "
            f"{ACTIVE_WINDOW_DAYS} days of the newest check-in; they are left out of every other endpoint check."
        )
        recommendations.append("Remove decommissioned endpoints from Sophos Central, or bring the dark ones back online.")
    elif machines:
        pass_reasons.append(f"All {len(machines)} Sophos computers and servers were seen within {ACTIVE_WINDOW_DAYS} days.")
    result = {criteriaKey: stale, "totalEndpoints": len(machines), "activeEndpoints": len(active),
              "activeWindowDays": ACTIVE_WINDOW_DAYS}
    return create_response(result=result, validation=validation, pass_reasons=pass_reasons,
                           fail_reasons=fail_reasons, recommendations=recommendations,
                           input_summary={"totalEndpoints": len(machines), "staleEndpoints": stale})
