"""
Transformation: isFirewallUpdated (THL NW-02: Routine Network Device Patching)
Vendor: Cisco Meraki MX  |  Category: firewalls
Source: GET /networks/{networkId}/firmwareUpgrades, fanned out over appliance networks
Value: the percentage of appliance networks whose MX runs the latest stable firmware Meraki
offers it (products.appliance: no releaseType "stable" entry in availableVersions newer than
currentVersion). The pass bar lives in the requirement.
A network with no appliance product, or a body that is not a firmwareUpgrades answer, is not
measured; no measured network means no value. This replaces the org-level upgrade-history
check, which passed on one completed upgrade and could not see a network left behind.
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


def appliance_firmware(response):
    """(current version, newer stable versions) for the MX on one network, or None when the
    body carries no appliance firmware (not an answer from this endpoint, or no MX)."""
    if not isinstance(response, dict):
        return None
    products = response.get("products")
    appliance = products.get("appliance") if isinstance(products, dict) else None
    if not isinstance(appliance, dict):
        return None
    current = appliance.get("currentVersion")
    if not isinstance(current, dict) or not (current.get("id") or current.get("firmware")):
        return None
    current_date = str(current.get("releaseDate") or "")
    newer = []
    for version in appliance.get("availableVersions") or []:
        if not isinstance(version, dict) or str(version.get("releaseType", "")).lower() != "stable":
            continue
        if version.get("id") == current.get("id") or (version.get("firmware") and version.get("firmware") == current.get("firmware")):
            continue
        version_date = str(version.get("releaseDate") or "")
        if current_date and version_date and version_date <= current_date:
            continue   # ISO-8601 dates compare in time order; an older stable is not an upgrade
        newer.append(version.get("shortName") or version.get("firmware") or str(version.get("id")))
    return current.get("shortName") or current.get("firmware") or str(current.get("id")), newer


def evaluate(data):
    reached, pairs = per_network(data, "items")
    current_nets, behind, unreadable = [], [], []
    for name, response in pairs:
        found = appliance_firmware(response)
        if found is None:
            unreadable.append(name)
            continue
        version, newer = found
        if newer:
            behind.append({"network": name, "current": version, "latestStable": newer[:3]})
        else:
            current_nets.append(name)
    measured = len(current_nets) + len(behind)
    coverage = pct(len(current_nets), measured) if reached else None
    result = {
        "isFirewallUpdated": coverage,
        "networksEvaluated": measured,
        "networksOnLatestStable": len(current_nets),
        "networksBehind": behind[:25],
        "networksNotMeasured": unreadable[:25],
        "endpointReached": reached,
    }
    passes, fails, recs, api_errors = [], [], [], []
    if not reached or measured == 0:
        api_errors.append(
            "No appliance network returned MX firmware (products.appliance.currentVersion), so "
            "firmware currency could not be measured."
        )
        fails.append(api_errors[0])
    else:
        if current_nets:
            passes.append("%d of %d appliance network(s) (%s%%) run the latest stable MX firmware."
                          % (len(current_nets), measured, coverage))
        if behind:
            fails.append("%d of %d appliance network(s) have a newer stable MX firmware available: %s."
                         % (len(behind), measured, ", ".join(b["network"] + " on " + str(b["current"]) for b in behind[:10])))
            recs.append("Schedule the latest stable MX firmware under Organization > Firmware upgrades for each network listed.")
    return result, passes, fails, recs, api_errors, {"networksEvaluated": measured, "networksNotMeasured": len(unreadable)}


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
        api_errors=api_errors,
        input_summary=input_summary,
        metadata={
            "transformationId": "isFirewallUpdated",
            "vendor": "Cisco Meraki MX",
            "category": "firewalls",
        },
    )
