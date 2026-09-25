"""
Transformation: isRecorderEventCollectionEnabled
Vendor: Trend Micro Vision One (Endpoint Security)  |  Category: Endpoint Security
Method: getEndpointSecurityEndpoints (GET {serverUrl}/v3.0/endpointSecurity/endpoints, nextLink pagination)

Evidence: the Endpoint Inventory list (response model: trendmicro/tm-v1-pytv1 EndpointSecurityEndpoint,
EppAgent, EdrSensor; field values: trendmicro/vision-one-mcp-server FilterEndpoints table).
Confirmed on a real Infraservices payload (417 endpoints, 2026-09-25).

Verdict: true when every endpoint has an endpoint sensor whose status is enabled (edrSensor.status,
"the status of the endpoint sensor detection and response") and whose connectivity is
connected. disabled, enabling, disabling, unknown, disconnected or no sensor fail it.

What this proves: every inventoried endpoint's activity recorder is switched on and connected
right now. What it does not prove: how much telemetry reached the data lake.

Fails closed: an error body, an unrecognised body, an empty endpoint list, or a merged
response that still carries nextLink (pages left unread) return false.
"""
import json
from datetime import datetime


VENDOR = "Trend Micro"
CATEGORY = "Endpoint Security"


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


def create_response(criteria_key, result, validation=None, pass_reasons=None, fail_reasons=None,
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": criteria_key, "vendor": VENDOR, "category": CATEGORY}
        }
    }


def api_error_message(data):
    """Vision One errors are {"error": {"code", "message"}}; Integration-Service errors carry status Error."""
    if not isinstance(data, dict):
        return None
    err = data.get("error")
    if isinstance(err, dict):
        return "Trend Vision One API error " + str(err.get("code") or "") + ": " + str(err.get("message") or "")
    if err is True or str(err).lower() == "true":
        return str(data.get("errorMessage") or data.get("message") or "Trend Vision One API returned an error")
    if str(data.get("status", "")).lower() == "error":
        return str(data.get("message") or data.get("errorMessage") or "Trend Vision One API returned an error")
    return None


def endpoint_items(data):
    if isinstance(data, dict):
        items = data.get("items")
        if isinstance(items, list):
            return [e for e in items if isinstance(e, dict)]
    return None


def unread_pages(data):
    """True when the merged response still carries a nextLink: pagination stopped early."""
    if isinstance(data, dict):
        link = data.get("nextLink")
        return isinstance(link, str) and link != ""
    return False


def endpoint_name(endpoint):
    return str(endpoint.get("endpointName") or endpoint.get("displayName") or endpoint.get("agentGuid") or "unnamed")


def sub(endpoint, key):
    block = endpoint.get(key)
    return block if isinstance(block, dict) else None


def load_endpoints(criteria_key, input, fail_value):
    """Returns (endpoints, validation, None) or (None, None, failure_response)."""
    if isinstance(input, str):
        input = json.loads(input)
    elif isinstance(input, bytes):
        input = json.loads(input.decode("utf-8"))
    data, validation = extract_input(input)
    if validation.get("status") == "failed":
        return None, None, create_response(criteria_key, {criteria_key: fail_value}, validation=validation,
                                           fail_reasons=["Input validation failed"])
    error = api_error_message(data)
    items = endpoint_items(data)
    if error or items is None:
        reason = error or "Endpoint list response not recognised - no items list present"
        return None, None, create_response(criteria_key, {criteria_key: fail_value}, validation=validation,
                                           api_errors=[reason], fail_reasons=[reason],
                                           recommendations=["Verify the API key can call GET /v3.0/endpointSecurity/endpoints (Endpoint Inventory: View) and that serverUrl is the tenant's regional API domain"])
    if unread_pages(data):
        reason = "The endpoint list has more pages than were read (nextLink still present)"
        return None, None, create_response(criteria_key, {criteria_key: fail_value}, validation=validation,
                                           api_errors=[reason], fail_reasons=[reason],
                                           recommendations=["Raise maxPages on getEndpointSecurityEndpoints"])
    if len(items) == 0:
        reason = "Trend Vision One returned no endpoints, so nothing about the estate is proven"
        return None, None, create_response(criteria_key, {criteria_key: fail_value}, validation=validation,
                                           fail_reasons=[reason],
                                           recommendations=["Confirm endpoints are managed in Trend Vision One Endpoint Inventory and that the API key's role can see them"])
    return items, validation, None


def failure(criteria_key, fail_value, error):
    return create_response(criteria_key, {criteria_key: fail_value},
                           validation={"status": "error", "errors": [], "warnings": []},
                           transformation_errors=[str(error)], fail_reasons=["Transformation error: " + str(error)])


def transform(input):
    criteriaKey = "isRecorderEventCollectionEnabled"
    try:
        endpoints, validation, failed = load_endpoints(criteriaKey, input, False)
        if failed:
            return failed
        no_sensor = []
        not_enabled = []
        disconnected = []
        collecting = 0
        for e in endpoints:
            sensor = sub(e, "edrSensor")
            if sensor is None:
                no_sensor.append(endpoint_name(e))
            elif sensor.get("status") != "enabled":
                not_enabled.append(endpoint_name(e))
            elif sensor.get("connectivity") != "connected":
                disconnected.append(endpoint_name(e))
            else:
                collecting = collecting + 1
        value = collecting == len(endpoints)
        summary = {"totalEndpoints": len(endpoints), "sensorsCollecting": collecting,
                   "sensorsNotEnabled": len(not_enabled), "sensorsDisconnected": len(disconnected),
                   "endpointsWithoutSensor": len(no_sensor), "sampleNotEnabled": not_enabled[:10],
                   "sampleDisconnected": disconnected[:10], "sampleWithoutSensor": no_sensor[:10]}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if value:
            pass_reasons.append("All %d endpoint sensors are enabled and connected" % len(endpoints))
        else:
            if not_enabled:
                fail_reasons.append("%d endpoint sensors are not enabled (detection and response off): %s" % (len(not_enabled), ", ".join(not_enabled[:10])))
            if disconnected:
                fail_reasons.append("%d enabled sensors are disconnected: %s" % (len(disconnected), ", ".join(disconnected[:10])))
            if no_sensor:
                fail_reasons.append("%d endpoints have no endpoint sensor: %s" % (len(no_sensor), ", ".join(no_sensor[:10])))
            recommendations.append("Turn on endpoint sensor detection and response in the endpoint policy and reconnect the listed endpoints")
        return create_response(criteriaKey, {criteriaKey: value, **summary}, validation=validation,
                               pass_reasons=pass_reasons, fail_reasons=fail_reasons,
                               recommendations=recommendations, input_summary=summary)
    except Exception as e:
        return failure(criteriaKey, False, e)
