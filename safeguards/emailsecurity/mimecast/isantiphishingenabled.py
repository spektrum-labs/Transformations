"""
Transformation: isAntiPhishingEnabled
Vendor: Mimecast
Category: Email Security / Anti-Phishing

Ensures that email filters are configured to block phishing and spam.
Checks for anti-phishing indicators, policies, and filters.
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
                "vendor": "Mimecast",
                "category": "Email Security"
            }
        }
    }


def transform(input):
    criteriaKey = "isAntiPhishingEnabled"

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

        antiphishing_enabled = False
        phishing_policies_count = 0
        filters_count = 0

        if isinstance(data, dict):
            if 'antiphishingEnabled' in data or 'phishingProtection' in data:
                antiphishing_enabled = bool(data.get('antiphishingEnabled', data.get('phishingProtection', False)))
            elif 'policies' in data:
                policies = data['policies'] if isinstance(data['policies'], list) else []
                phishing_policies = [p for p in policies if 'phishing' in str(p).lower() or 'spam' in str(p).lower()]
                phishing_policies_count = len(phishing_policies)
                antiphishing_enabled = phishing_policies_count > 0
            elif 'filters' in data:
                filters = data['filters'] if isinstance(data['filters'], list) else []
                filters_count = len(filters)
                antiphishing_enabled = filters_count > 0
            elif 'enabled' in data:
                antiphishing_enabled = bool(data['enabled'])

        if antiphishing_enabled:
            reason = "Anti-phishing protection is enabled"
            if phishing_policies_count > 0:
                reason += f" ({phishing_policies_count} phishing/spam policies configured)"
            elif filters_count > 0:
                reason += f" ({filters_count} filters configured)"
            pass_reasons.append(reason)
        else:
            fail_reasons.append("Anti-phishing protection is not enabled")
            recommendations.append("Configure anti-phishing and spam filters in Mimecast")

        return create_response(
            result={
                criteriaKey: antiphishing_enabled,
                "phishingPolicies": phishing_policies_count,
                "filtersCount": filters_count
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "phishingPolicies": phishing_policies_count,
                "filtersCount": filters_count
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
