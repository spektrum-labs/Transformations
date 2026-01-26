"""
Transformation: isAntiPhishingEnabled
Vendor: Email Security Provider
Category: Email Security

Evaluates Mail Policies to check for Anti-Phishing settings including
domain spoofing and employee name spoofing detection.
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
                "transformationId": "isAntiPhishingEnabled",
                "vendor": "Email Security Provider",
                "category": "Email Security"
            }
        }
    }


def transform(input):
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={"isEmailSecurityEnabled": False, "isAntiPhishingEnabled": False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        filter_attributes = ["detectDomainNameSpoofing", "detectEmployeeNameSpoofing"]

        policies = []
        if isinstance(data, dict):
            policies = data.get("policies", [])

        matching_values = []
        for policy in policies:
            if isinstance(policy, dict) and "setting" in policy:
                setting = policy.get("setting", {})
                value = setting.get("value", {}) if isinstance(setting, dict) else {}
                if isinstance(value, dict):
                    filtered = {key: value[key] for key in value if key in filter_attributes}
                    if filtered:
                        matching_values.append(filtered)

        isAntiPhishingEnabled = False
        isEmailSecurityEnabled = False

        if len(policies) > 0:
            isEmailSecurityEnabled = True
            pass_reasons.append(f"Email security policies configured: {len(policies)} policies")

        # If any of the matching values are None or False, set isAntiPhishingEnabled to False
        if len(matching_values) > 0:
            isAntiPhishingEnabled = True
            for mv in matching_values:
                for key, value in mv.items():
                    if value is None or not bool(value):
                        isAntiPhishingEnabled = False
                        break
                if not isAntiPhishingEnabled:
                    break

        if isAntiPhishingEnabled:
            pass_reasons.append("Anti-phishing protection enabled (domain/employee spoofing detection)")
        else:
            if len(policies) > 0:
                fail_reasons.append("Anti-phishing protection not fully enabled in policies")
            else:
                fail_reasons.append("No email security policies configured")
            recommendations.append("Enable domain name spoofing and employee name spoofing detection")

        return create_response(
            result={
                "isEmailSecurityEnabled": isEmailSecurityEnabled,
                "isAntiPhishingEnabled": isAntiPhishingEnabled,
                "policyDetails": matching_values
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "totalPolicies": len(policies),
                "antiPhishingPolicies": len(matching_values)
            }
        )

    except Exception as e:
        return create_response(
            result={"isEmailSecurityEnabled": False, "isAntiPhishingEnabled": False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
