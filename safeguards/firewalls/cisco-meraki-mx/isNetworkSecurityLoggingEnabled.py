"""
Transformation: isNetworkSecurityLoggingEnabled
Vendor: Cisco Meraki MX  |  Category: firewalls
Source: GET /networks/{networkId}/syslogServers, fanned out over appliance networks
Pass: every appliance network forwards the 'Security events' or 'IDS alerts' role to a
syslog server - the intrusion and malware record. Distinct from isFirewallLoggingEnabled,
which covers flows and appliance events.
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


WANTED_ROLES = ['ids alerts', 'security events']


def evaluate(data):
    reached, pairs = per_network(data, "syslogServers")
    covered, missing, unreadable = [], [], []
    for name, response in pairs:
        servers = response.get("servers") if isinstance(response, dict) else None
        if not isinstance(servers, list):
            unreadable.append(name)
            continue
        found = False
        for server in servers:
            server_roles = server.get("roles") if isinstance(server, dict) else None
            if isinstance(server_roles, list):
                for role in server_roles:
                    if str(role).strip().lower() in WANTED_ROLES:
                        found = True
        (covered if found else missing).append(name)
    measured = len(covered) + len(missing)
    result = {
        "isNetworkSecurityLoggingEnabled": reached and measured > 0 and not missing and not unreadable,
        "syslogCoveragePercentage": pct(len(covered), measured),
        "networksEvaluated": measured,
        "networksWithoutRole": missing[:25],
        "networksNotMeasured": unreadable[:25],
        "requiredRoles": ['IDS alerts', 'Security events'],
        "endpointReached": reached,
    }
    passes, fails, recs = [], [], []
    if not reached:

        fails.append(
            "The response carries no appliance network list and no per-network results, "
            "so it is indistinguishable from an authentication failure. Not measured."
        )

    elif measured == 0:
        fails.append("No appliance network returned syslog server settings.")
    elif not missing and not unreadable:
        passes.append(
            "All %d appliance network(s) forward security events or IDS alerts to a syslog server." % measured
        )
    else:
        fails.append(
            "%d of %d appliance network(s) forward no security events or IDS alerts to syslog: %s."
            % (len(missing), measured, ", ".join(missing[:10]))
        )
        recs.append('Add the Security events and IDS alerts roles to a syslog server under Network-wide > General on each network listed.')
    return result, passes, fails, recs, {"networksEvaluated": measured}


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
            "transformationId": "isNetworkSecurityLoggingEnabled",
            "vendor": "Cisco Meraki MX",
            "category": "firewalls",
        },
    )
