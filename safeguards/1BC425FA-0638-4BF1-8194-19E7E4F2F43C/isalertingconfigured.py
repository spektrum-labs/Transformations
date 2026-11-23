"""
Transformation: isAlertingConfigured
Vendor: Sophos Central - MDR  |  Category: MDR
Method: getEndpoints (GET /endpoint/v1/endpoints)

Sophos MDR alerting runs from the endpoint: the agent's detection and telemetry services
raise detections to Sophos Central, and for an MDR-managed endpoint the Sophos MDR
operations team triages them. Alerting is therefore in effect on an endpoint when it is
under MDR (mdrManaged, or the mtr/xdr products installed, with the core agent) AND Sophos
reports all of its agent services running (health.services.status == "good").

Only endpoints seen within 7 days of the newest lastSeenAt in the response are judged; stale
endpoints are counted and returned, not silently dropped.

What this proves: every active endpoint is feeding detections into the Sophos MDR service.
What it does not prove: notification routing to named people (escalation contacts, the
MDR "authorized" response mode) or alerting for non-endpoint sources; the endpoints API
does not expose them.

Verdict: true when at least one active endpoint exists and every active endpoint is
MDR-covered with its services healthy.
"""
import json
from datetime import datetime, timedelta


MDR_PRODUCT_CODES = ("mtr", "xdr")
ACTIVE_WINDOW_DAYS = 7


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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isAlertingConfigured", "vendor": "Sophos Central - MDR", "category": "MDR"}
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
    if isinstance(data, dict):
        if data.get("error") is True or str(data.get("error")).lower() in ("true", "forbidden", "unauthorized"):
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
    active = []
    stale = 0
    for endpoint, when in zip(endpoints, seen):
        if when is not None and when < cutoff:
            stale = stale + 1
        else:
            active.append(endpoint)
    return active, stale


def installed_codes(endpoint):
    return [p.get("code") for p in (endpoint.get("assignedProducts") or [])
            if isinstance(p, dict) and p.get("status") == "installed"]


def mdr_covered(endpoint):
    """Sophos only assigns mtr/xdr, and marks mdrManaged, on endpoints under the MDR service."""
    managed = str(endpoint.get("mdrManaged")).strip().lower() == "true"
    codes = installed_codes(endpoint)
    return (managed or any(c in MDR_PRODUCT_CODES for c in codes)) and "coreAgent" in codes


def label(endpoint):
    return endpoint.get("hostname") or endpoint.get("id") or "unknown"


def transform(input):
    criteriaKey = "isAlertingConfigured"
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
                                   recommendations=["Verify the Sophos endpoints API (/endpoint/v1/endpoints) is readable for this tenant"])

        active, stale = active_endpoints(items)
        alerting = [e for e in active if mdr_covered(e) and
                    ((e.get("health") or {}).get("services") or {}).get("status") == "good"]
        not_alerting = [label(e) for e in active if e not in alerting]
        pct = round((len(alerting) / len(active)) * 100) if active else 0
        value = len(active) > 0 and len(not_alerting) == 0

        summary = {
            "activeEndpoints": len(active),
            "endpointsAlertingToMDR": len(alerting),
            "alertingPercentage": pct,
            "endpointsNotAlerting": not_alerting[:20],
            "staleEndpointsExcluded": stale,
        }
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if not active:
            fail_reasons.append("No active endpoint reported to Sophos Central")
            recommendations.append("Deploy the Sophos agent and confirm endpoints check in")
        elif value:
            pass_reasons.append(f"All {len(active)} active endpoint(s) are MDR-managed with healthy detection services")
        else:
            fail_reasons.append(f"{len(not_alerting)} of {len(active)} active endpoint(s) are outside MDR or report stopped Sophos services")
            recommendations.append("Restore Sophos services or assign MDR on: " + ", ".join(str(h) for h in not_alerting[:20]))

        return create_response(result={criteriaKey: value, **summary}, validation=validation,
                               pass_reasons=pass_reasons, fail_reasons=fail_reasons,
                               recommendations=recommendations, input_summary={criteriaKey: value, **summary})
    except Exception as e:
        return create_response(result={criteriaKey: False},
                               validation={"status": "error", "errors": [], "warnings": []},
                               transformation_errors=[str(e)], fail_reasons=[f"Transformation error: {str(e)}"])
