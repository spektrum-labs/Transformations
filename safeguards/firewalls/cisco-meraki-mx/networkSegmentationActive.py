"""
Transformation: networkSegmentationActive
Vendor: Cisco Meraki MX  |  Category: firewalls
Source: GET /networks/{networkId}/appliance/vlans/settings, fanned out over appliance networks
Pass: every appliance network has VLANs enabled. A network with VLANs disabled is a single
flat LAN behind the MX. This replaces networksecurity/meraki/networksegmentationactive.py,
which counted networks and passed any organization with two flat sites.
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


def as_flag(value):
    """True or False for a boolean, for 0 or 1, or for the text true/false; None for anything else.

    A text flag must not be read by its truthiness: the text "false" is not empty."""
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return value == 1
    if isinstance(value, str):
        text = value.strip().lower()
        if text == "true":
            return True
        if text == "false":
            return False
    return None


def evaluate(data):
    reached, pairs = per_network(data, "vlanSettings")
    segmented, flat, unreadable = [], [], []
    for name, response in pairs:
        flag = as_flag(response.get("vlansEnabled")) if isinstance(response, dict) else None
        if flag is None:
            unreadable.append(name)
        elif flag:
            segmented.append(name)
        else:
            flat.append(name)
    measured = len(segmented) + len(flat)
    if not reached or measured == 0:
        verdict = None
    elif flat:
        verdict = False
    elif unreadable:
        verdict = None
    else:
        verdict = True
    result = {
        "networkSegmentationActive": verdict,
        "vlanCoveragePercentage": pct(len(segmented), measured),
        "networksEvaluated": measured,
        "flatNetworks": flat[:25],
        "networksNotMeasured": unreadable[:25],
        "endpointReached": reached,
    }
    passes, fails, recs, api_errors = [], [], [], []
    if not reached:
        api_errors.append(
            "The Meraki response carries no appliance network list and no per-network results; "
            "nothing to measure."
        )
    elif measured == 0:
        api_errors.append("No appliance network returned VLAN settings; nothing to measure.")
    elif flat:
        fails.append(
            "%d of %d appliance network(s) run a single flat LAN with VLANs disabled: %s."
            % (len(flat), measured, ", ".join(flat[:10]))
        )
        recs.append(
            "Enable VLANs under Security & SD-WAN > Addressing & VLANs and separate user, "
            "server and OT/IoT traffic on each network listed."
        )
    elif unreadable:
        api_errors.append(
            "%d of %d appliance network(s) could not be read (%s), so VLAN segmentation cannot be confirmed on every network."
            % (len(unreadable), len(unreadable) + measured, ", ".join(unreadable[:10]))
        )
    else:
        passes.append(
            "All %d appliance network(s) have VLANs enabled." % measured
        )
    if api_errors:
        fails = list(api_errors)
    elif unreadable:
        fails.append("%d more network(s) could not be read and were not counted: %s." % (len(unreadable), ", ".join(unreadable[:10])))
    return result, passes, fails, recs, api_errors, {"networksEvaluated": measured}


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}
    result, pass_reasons, fail_reasons, recommendations, api_errors, input_summary = evaluate(data)
    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        api_errors=api_errors,
        metadata={
            "transformationId": "networkSegmentationActive",
            "vendor": "Cisco Meraki MX",
            "category": "firewalls",
        },
    )
