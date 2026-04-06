"""
Transformation: hasActiveNetworkSites
Vendor: DNSFilter
Category: Network Security

Validates at least one network site is configured and protected.
"""

import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
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
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "hasActiveNetworkSites", "vendor": "DNSFilter", "category": "Network Security"}
        }
    }

def transform(input):
    criteriaKey = "hasActiveNetworkSites"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        networks = data if isinstance(data, list) else data.get("networks", []) if isinstance(data, dict) else []
        active_count = 0

        for network in networks:
            if not isinstance(network, dict):
                continue
            policy_id = network.get("policy_id")
            status = str(network.get("status", "active")).lower()
            if policy_id and status in ("active", "protected"):
                active_count = active_count + 1

        has_active = active_count > 0

        if has_active:
            pass_reasons.append(f"{active_count} active network site(s) configured with filtering policies")
        else:
            fail_reasons.append("No active network sites with filtering policies found")
            recommendations.append("Configure at least one network site with a filtering policy in DNSFilter")

        return create_response(
            result={criteriaKey: has_active, "networkCount": active_count, "totalNetworks": len(networks)},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"activeNetworks": active_count, "totalNetworks": len(networks)}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
