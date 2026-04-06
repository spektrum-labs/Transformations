"""
Transformation: isThreatProtectionEnabled
Vendor: DNSFilter
Category: Network Security

Verifies core threat categories are blocked in policies.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isThreatProtectionEnabled", "vendor": "DNSFilter", "category": "Network Security"}
        }
    }

def transform(input):
    criteriaKey = "isThreatProtectionEnabled"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        required_categories = {"malware", "phishing", "botnet"}

        policies = data if isinstance(data, list) else []
        if isinstance(data, dict):
            policies = data.get("policies", [])

        if not policies:
            fail_reasons.append("No filtering policies found")
            recommendations.append("Configure filtering policies with malware, phishing, and botnet categories blocked")
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=fail_reasons,
                recommendations=recommendations,
                input_summary={"policyCount": 0}
            )

        is_enabled = False
        blocked_names = set()

        for policy in policies:
            if not isinstance(policy, dict):
                continue
            blacklisted = policy.get("blacklisted_categories", [])
            for cat in blacklisted:
                if isinstance(cat, dict):
                    name = cat.get("name", "").lower()
                elif isinstance(cat, str):
                    name = cat.lower()
                else:
                    continue
                blocked_names.add(name)

            if required_categories.issubset(blocked_names):
                is_enabled = True
                break

        if is_enabled:
            pass_reasons.append("Core threat categories (malware, phishing, botnet) are all blocked")
        else:
            missing = required_categories - blocked_names
            fail_reasons.append(f"Missing threat categories: {', '.join(sorted(missing))}")
            recommendations.append("Block malware, phishing, and botnet categories in DNSFilter policies")

        return create_response(
            result={criteriaKey: is_enabled, "blockedCategories": list(blocked_names)},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"policyCount": len(policies), "blockedCategoryCount": len(blocked_names)}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
