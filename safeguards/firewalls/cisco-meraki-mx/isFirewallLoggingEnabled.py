"""Cisco Meraki MX - isFirewallLoggingEnabled (THL NW-01: Config and Change Monitoring).

Reads GET /networks/{networkId}/syslogServers, iterated across the organisation's
appliance networks, so the input is normally a list of per-network responses.

Passes when at least one syslog server is configured anywhere in the estate. The
roles seen ('Flows', 'URLs', 'Security events', 'Appliance event log') are reported
rather than required: NW-01 asks that monitoring exists, not which feeds are on.
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
        for _ in range(3):
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
    data_collection_status = "error" if api_err_list else "success"
    transformation_status = "error" if transform_err_list else "success"
    response_metadata = {
        "evaluatedAt": datetime.utcnow().isoformat() + "Z",
        "schemaVersion": "2.0",
    }
    if metadata:
        response_metadata.update(metadata)
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": data_collection_status, "errors": api_err_list},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": transformation_status,
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


def transform(input):
    criteriaKey = "isFirewallLoggingEnabled"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        def _is_server_obj(candidate):
            return isinstance(candidate, dict) and (
                "host" in candidate or "server" in candidate
            )

        def _servers_from_payload(payload):
            if isinstance(payload, dict):
                if "servers" in payload:
                    servers = payload["servers"]
                    if isinstance(servers, list):
                        return [s for s in servers if _is_server_obj(s)]
                    if _is_server_obj(servers):
                        return [servers]
                    return []

                if _is_server_obj(payload):
                    return [payload]
            elif isinstance(payload, list):
                return [s for s in payload if _is_server_obj(s)]

            return []

        if isinstance(data, list) and data and all(_is_server_obj(item) for item in data):
            network_payloads = [data]
        elif isinstance(data, list):
            network_payloads = data
        else:
            network_payloads = [data]

        all_servers = []
        networks_with_servers = 0
        roles_seen = set()

        for payload in network_payloads:
            servers = _servers_from_payload(payload)

            if servers:
                networks_with_servers += 1
                all_servers.extend(servers)

                for server in servers:
                    roles = server.get("roles", [])
                    if isinstance(roles, str):
                        roles_seen.add(roles)
                    elif isinstance(roles, list):
                        for role in roles:
                            roles_seen.add(str(role))

        server_count = len(all_servers)
        roles_seen_list = sorted(roles_seen)
        enabled = server_count > 0

        if enabled:
            role_summary = ", ".join(roles_seen_list) if roles_seen_list else "None"
            pass_reasons = [
                f"{server_count} syslog server(s) configured across {networks_with_servers} network(s). "
                f"Roles seen: {role_summary}."
            ]
            fail_reasons = []
            recommendations = []
        else:
            pass_reasons = []
            fail_reasons = [
                "No syslog servers are configured across the Meraki MX networks."
            ]
            recommendations = [
                "Configure syslog servers for firewall logs (Flows, URLs, Security events, Appliance event log) to enable network configuration and change monitoring."
            ]

        result = {
            criteriaKey: enabled,
            "serverCount": server_count,
            "networksWithServers": networks_with_servers,
            "rolesSeen": roles_seen_list,
        }

        return create_response(
            result=result,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "serverCount": server_count,
                "networksWithServers": networks_with_servers,
                "rolesSeen": roles_seen_list,
            },
            metadata={
                "transformationId": criteriaKey,
                "vendor": "Cisco Meraki MX",
                "category": "firewalls",
            },
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
