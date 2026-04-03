"""
Transformation: isAntiPhishingEnabled
Vendor: Mimecast
Category: Email Security / Anti-Phishing

Evaluates whether Mimecast anti-phishing protection is active by checking
anti-spoofing bypass policies from /api/policy/antispoofing-bypass/get-policy.
Anti-spoofing policies directly indicate active phishing protection since
sender spoofing is the primary vector for phishing attacks.
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
        policy_count = 0

        if isinstance(data, dict):
            # /api/policy/antispoofing-bypass/get-policy returns policies
            # in a "data" array (mapped as "policies" in returnSpec).
            # A successful response confirms anti-spoofing is configured,
            # which is a direct indicator of active phishing protection.
            policies = data.get('policies', data.get('data', []))
            if isinstance(policies, list):
                policy_count = len(policies)
                antiphishing_enabled = policy_count > 0

        if antiphishing_enabled:
            pass_reasons.append(
                f"Mimecast anti-phishing is configured ({policy_count} anti-spoofing "
                f"polic{'y' if policy_count == 1 else 'ies'} active)"
            )
        else:
            fail_reasons.append("No anti-spoofing policies configured in Mimecast")
            recommendations.append("Configure anti-spoofing policies in Mimecast to protect against phishing attacks")

        return create_response(
            result={
                criteriaKey: antiphishing_enabled,
                "policyCount": policy_count
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "antiphishingActive": antiphishing_enabled,
                "policyCount": policy_count
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
