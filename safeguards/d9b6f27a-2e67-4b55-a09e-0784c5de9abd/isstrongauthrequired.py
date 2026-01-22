"""
Transformation: isStrongAuthRequired
Vendor: Microsoft
Category: Identity / Authentication

Evaluates if strong authentication is required by checking for active authentication policies.
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
                    recommendations=None, input_summary=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "validationStatus": validation.get("status", "unknown"),
            "validationErrors": validation.get("errors", []),
            "validationWarnings": validation.get("warnings", []),
            "passReasons": pass_reasons or [],
            "failReasons": fail_reasons or [],
            "recommendations": recommendations or [],
            "inputSummary": input_summary or {},
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "isStrongAuthRequired",
                "vendor": "Microsoft",
                "category": "Identity"
            }
        }
    }


def transform(input):
    criteriaKey = "isStrongAuthRequired"

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

        # Check for list input (authentication policies)
        if isinstance(data, list):
            policies = data
        else:
            policies = data.get('response', data) if isinstance(data, dict) else []
            if isinstance(policies, dict):
                policies = [policies]

        # Check for active authentication policies
        is_required = False
        active_count = 0
        for item in policies:
            if isinstance(item, dict) and item.get('status', '').lower() == 'active':
                is_required = True
                active_count += 1

        if is_required:
            pass_reasons.append(f"Strong authentication is required with {active_count} active policy(ies)")
        else:
            fail_reasons.append("No active strong authentication policies found")
            recommendations.append("Enable strong authentication requirements in Azure AD")

        return create_response(
            result={criteriaKey: is_required},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"activePolicies": active_count}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [str(e)], "warnings": []},
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
