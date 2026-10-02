"""
Transformation: offlineSensorCount
Vendor: Trend Micro Vision One (Endpoint Security)  |  Category: Endpoint Security
Method: getEndpointSecurityEndpoints (GET {serverUrl}/v3.0/endpointSecurity/endpoints, nextLink pagination)

Evidence: the Endpoint Inventory list. Field names and values are the ones Trend Micro
documents for this API (filter table in trendmicro/vision-one-mcp-server
internal/v1mcp/tooldescriptions FilterEndpoints; response model in trendmicro/tm-v1-pytv1
EndpointSecurityEndpoint): items[].type (desktop|server), isolationStatus (on|off|unknown),
eppAgent.status (on|off|unknown, the protection agent connectivity status),
eppAgent.componentVersion (outdatedVersion|latestVersion|unknownVersions|controlledLatestVersion),
edrSensor.status (enabled|disabled|enabling|disabling|unknown),
edrSensor.connectivity (connected|disconnected). eppAgent / edrSensor are absent when the
endpoint has no protection agent / no sensor.

Fails closed: an error body, an unrecognised body, an empty endpoint list, or a merged
response that still carries nextLink (pages left unread) all return None
(no count), so an "equals 0" check cannot pass.

Value: the number of endpoints that have an endpoint sensor (edrSensor block) whose
connectivity is not "connected". Endpoints with no sensor are not counted here
(isEDRDeployed fails for them). If no endpoint has a sensor, the value is None.

What this proves: how many installed Trend endpoint sensors are not reporting in.
What it does not prove: protection agent connectivity, which is eppAgent.status.
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
    criteriaKey = "offlineSensorCount"
    try:
        endpoints, validation, failed = load_endpoints(criteriaKey, input, None)
        if failed:
            return failed
        sensors = 0
        offline = []
        for e in endpoints:
            sensor = sub(e, "edrSensor")
            if sensor is None:
                continue
            sensors = sensors + 1
            if sensor.get("connectivity") != "connected":
                offline.append(endpoint_name(e) + " (" + str(sensor.get("connectivity")) + ")")
        value = len(offline) if sensors > 0 else None
        summary = {"totalEndpoints": len(endpoints), "endpointsWithSensor": sensors,
                   "offlineSensors": len(offline), "sampleOffline": offline[:10]}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if sensors == 0:
            fail_reasons.append("No endpoint has a Trend endpoint sensor, so there is no sensor connectivity to count")
        elif offline:
            fail_reasons.append("%d of %d endpoint sensors are not connected: %s" % (len(offline), sensors, ", ".join(offline[:10])))
            recommendations.append("Check network reachability of the listed endpoints to Trend Vision One, or retire them from Endpoint Inventory")
        else:
            pass_reasons.append("All %d endpoint sensors are connected" % sensors)
        return create_response(criteriaKey, {criteriaKey: value, **summary}, validation=validation,
                               pass_reasons=pass_reasons, fail_reasons=fail_reasons,
                               recommendations=recommendations, input_summary=summary)
    except Exception as e:
        return failure(criteriaKey, None, e)
