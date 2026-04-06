"""
Transformation: isNewDomainProtectionEnabled
Vendor: DNSFilter
Category: Network Security

Verifies new domain categories are blocked in policies.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isNewDomainProtectionEnabled", "vendor": "DNSFilter", "category": "Network Security"}
        }
    }

def transform(input):
    criteriaKey = "isNewDomainProtectionEnabled"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        policies = data if isinstance(data, list) else []
        if isinstance(data, dict):
            policies = data.get("policies", [])

        if not policies:
            fail_reasons.append("No filtering policies found")
            recommendations.append("Block new domain categories in DNSFilter policies")
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=fail_reasons,
                recommendations=recommendations,
                input_summary={"policyCount": 0}
            )

        is_enabled = False
        has_new_domains = False
        has_very_new_domains = False

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
                if "very new domain" in name:
                    has_very_new_domains = True
                elif "new domain" in name:
                    has_new_domains = True

        is_enabled = has_new_domains or has_very_new_domains

        if has_very_new_domains:
            additional_findings.append("Very new domains (< 24 hours) are blocked")
        if has_new_domains:
            additional_findings.append("New domains (< 30 days) are blocked")

        if is_enabled:
            pass_reasons.append("New domain protection is enabled in filtering policies")
        else:
            fail_reasons.append("New domain categories not blocked in any policy")
            recommendations.append("Block 'New Domains' and 'Very New Domains' categories in DNSFilter policies")

        return create_response(
            result={criteriaKey: is_enabled, "veryNewDomainsBlocked": has_very_new_domains, "newDomainsBlocked": has_new_domains},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"policyCount": len(policies)}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
