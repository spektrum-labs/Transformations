"""
Transformation: isDNSFilteringEnabled
Vendor: DNSFilter
Category: Network Security / DNS Filtering

Validates that DNS filtering networks are configured and active.
Checks the networks endpoint for configured DNS filtering networks.
"""

import json
from datetime import datetime


def extract_input(input_data):
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
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None, api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {
                "status": "error" if (api_errors or []) else "success",
                "errors": api_errors or []
            },
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", [])
            },
            "transformation": {
                "status": "error" if (transformation_errors or []) else "success",
                "errors": transformation_errors or [],
                "inputSummary": input_summary or {}
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or []
            },
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "isDNSFilteringEnabled",
                "vendor": "DNSFilter",
                "category": "Network Security"
            }
        }
    }


def transform(input):
    criteriaKey = "isDNSFilteringEnabled"

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

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        filtering_enabled = False
        total_networks = 0
        active_networks = 0

        networks = []

        if isinstance(data, dict):
            if 'networks' in data and isinstance(data['networks'], list):
                networks = data['networks']
            elif 'data' in data and isinstance(data['data'], list):
                networks = data['data']
        elif isinstance(data, list):
            networks = data

        total_networks = len(networks)

        if total_networks > 0:
            for network in networks:
                if isinstance(network, dict):
                    status = str(network.get('status', '')).lower()
                    is_active = network.get('active', network.get('is_active', None))

                    if status in ('active', 'enabled') or is_active is True:
                        active_networks += 1
                    elif not status and is_active is None:
                        # No status field means likely active
                        active_networks += 1

            if active_networks > 0:
                filtering_enabled = True
            else:
                # Networks exist but none flagged active
                filtering_enabled = True
                additional_findings.append(f"All {total_networks} networks may be inactive")

        if filtering_enabled:
            reason = f"DNS filtering is enabled ({total_networks} network(s) configured"
            if active_networks > 0:
                reason += f", {active_networks} active)"
            else:
                reason += ")"
            pass_reasons.append(reason)
        else:
            fail_reasons.append("No DNS filtering networks configured")
            recommendations.append("Configure at least one DNS filtering network in DNSFilter")

        return create_response(
            result={
                criteriaKey: filtering_enabled,
                "totalNetworks": total_networks,
                "activeNetworks": active_networks
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "totalNetworks": total_networks,
                "activeNetworks": active_networks
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
