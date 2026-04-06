"""
Transformation: isPhishingProtectionEnabled
Vendor: DNSFilter
Category: Network Security

Confirms phishing category is blocked in filtering policies.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isPhishingProtectionEnabled", "vendor": "DNSFilter", "category": "Network Security"}
        }
    }

def transform(input):
    criteriaKey = "isPhishingProtectionEnabled"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        policies = data if isinstance(data, list) else []
        if isinstance(data, dict):
            policies = data.get("policies", [])

        if not policies:
            fail_reasons.append("No filtering policies found")
            recommendations.append("Block phishing categories in DNSFilter policies")
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=fail_reasons,
                recommendations=recommendations,
                input_summary={"policyCount": 0}
            )

        is_enabled = False
        for policy in policies:
            if not isinstance(policy, dict):
                continue
            blacklisted = policy.get("blacklisted_categories", [])
            for cat in blacklisted:
                name = ""
                if isinstance(cat, dict):
                    name = cat.get("name", "").lower()
                elif isinstance(cat, str):
                    name = cat.lower()
                if "phishing" in name:
                    is_enabled = True
                    break
            if is_enabled:
                break

        if is_enabled:
            pass_reasons.append("Phishing protection is enabled in filtering policies")
        else:
            fail_reasons.append("Phishing category not blocked in any policy")
            recommendations.append("Block phishing categories in DNSFilter policies")

        return create_response(
            result={criteriaKey: is_enabled},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"policyCount": len(policies), "isPhishingProtectionEnabled": is_enabled}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
