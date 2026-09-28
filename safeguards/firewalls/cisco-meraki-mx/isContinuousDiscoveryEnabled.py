"""
Transformation: isContinuousDiscoveryEnabled
Vendor: Cisco Meraki MX  |  Category: firewalls
Source: GET /organizations/{organizationId}/devices
Pass: the organization's device inventory is readable and returns at least one device, so
the estate under assessment is enumerated rather than assumed.
"""
import json
from datetime import datetime


def extract_input(input_data):
    """Extract data and validation from input, handling enriched + legacy formats."""
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for step in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    validation = {
        "status": "unknown",
        "errors": [],
        "warnings": ["Legacy input format - no schema validation performed"],
    }
    return data, validation


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None,
                    transformation_errors=None, api_errors=None, additional_findings=None):
    """Create the standardized 5-section transformation response."""
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    transform_err_list = transformation_errors or []
    response_metadata = {
        "evaluatedAt": datetime.utcnow().isoformat() + "Z",
        "schemaVersion": "2.0",
    }
    if metadata:
        response_metadata.update(metadata)
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if api_err_list else "success", "errors": api_err_list},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": "error" if transform_err_list else "success",
                "errors": transform_err_list,
                "inputSummary": input_summary or {},
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or [],
            },
            "metadata": response_metadata,
        },
    }


def pct(numerator, denominator):
    if not denominator:
        return None
    return round((numerator / denominator) * 100, 2)


def unwrap_item(item):
    """A fanned-out response may still carry an apiResponse envelope."""
    for step in range(3):
        if not isinstance(item, dict):
            return item
        inner = item.get("apiResponse")
        if isinstance(inner, (dict, list)):
            item = inner
        else:
            break
    return item


def per_network(data, key):
    """Pair each appliance network with its fanned-out response.

    The workflow lists appliance networks, then calls the network-scoped
    endpoint once per network. The responses arrive either as a bare list or at
    `key` beside the `networks` list, in the same order. Returns (reached, pairs): reached is
    False when the payload carries neither list, which is indistinguishable from
    an authentication failure and must not be scored.
    """
    if isinstance(data, list):
        networks, responses = [], data
    elif isinstance(data, dict):
        networks = data.get("networks")
        responses = data.get(key)
    else:
        return False, []
    if not isinstance(networks, list) and not isinstance(responses, list):
        return False, []
    networks = networks if isinstance(networks, list) else []
    responses = responses if isinstance(responses, list) else []
    pairs = []
    for index in range(max(len(networks), len(responses))):
        network = networks[index] if index < len(networks) and isinstance(networks[index], dict) else {}
        name = network.get("name") or network.get("id") or "network[%d]" % index
        response = unwrap_item(responses[index]) if index < len(responses) else None
        pairs.append((name, response))
    return True, pairs


def evaluate(data):
    devices = data if isinstance(data, list) else None
    if devices is None and isinstance(data, dict):
        for key in ("devices", "items"):
            if isinstance(data.get(key), list):
                devices = data.get(key)
                break
    reached = isinstance(devices, list)
    devices = [d for d in (devices or []) if isinstance(d, dict) and (d.get("serial") or d.get("mac"))]
    by_type = {}
    for device in devices:
        kind = str(device.get("productType") or "unknown")
        by_type[kind] = by_type.get(kind, 0) + 1
    result = {
        "isContinuousDiscoveryEnabled": reached and len(devices) > 0,
        "deviceCount": len(devices),
        "applianceCount": by_type.get("appliance", 0),
        "productTypeBreakdown": by_type,
        "endpointReached": reached,
    }
    passes, fails, recs = [], [], []
    if not reached:
        fails.append(
            "The response carries no device list, so it is indistinguishable from an "
            "authentication failure. Not measured."
        )
    elif devices:
        passes.append(
            "Device inventory is readable: %d device(s), %d of them MX appliances."
            % (len(devices), by_type.get("appliance", 0))
        )
    else:
        fails.append("The organization returned an empty device inventory.")
    return result, passes, fails, recs, {"deviceCount": len(devices)}


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}
    result, pass_reasons, fail_reasons, recommendations, input_summary = evaluate(data)
    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isContinuousDiscoveryEnabled",
            "vendor": "Cisco Meraki MX",
            "category": "firewalls",
        },
    )
