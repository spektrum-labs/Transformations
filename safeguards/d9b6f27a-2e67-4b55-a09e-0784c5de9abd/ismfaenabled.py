"""
Transformation: isMFAEnabled
Vendor: Microsoft
Category: Identity / MFA

Evaluates if MFA is enabled for the environment via conditional access policies.
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
                    recommendations=None, input_summary=None, transformation_errors=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "validationStatus": validation.get("status", "unknown"),
            "validationErrors": validation.get("errors", []),
            "validationWarnings": validation.get("warnings", []),
            "transformationErrors": transformation_errors or [],
            "passReasons": pass_reasons or [],

            "failReasons": fail_reasons or [],
            "recommendations": recommendations or [],
            "inputSummary": input_summary or {},
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "isMFAEnabled",
                "vendor": "Microsoft",
                "category": "Identity"
            }
        }
    }


def transform(input):
    criteriaKey = "isMFAEnabled"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: False, "policiesTotal": 0, "policiesWithMFA": 0, "policiesWithoutMFA": 0},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        policies = data.get('value', [])
        policies_with_mfa = []
        policies_without_mfa = []

        for policy in policies:
            built_in_controls = policy.get("grantControls", {}).get("builtInControls", [])
            requires_mfa = "mfa" in built_in_controls

            if requires_mfa:
                policies_with_mfa.append(policy.get("displayName"))
            else:
                policies_without_mfa.append(policy.get("displayName"))

        is_enabled = len(policies_with_mfa) > 0

        if is_enabled:
            pass_reasons.append(f"MFA enabled via {len(policies_with_mfa)} conditional access policy(ies): {', '.join(policies_with_mfa[:3])}")
        else:
            fail_reasons.append("No conditional access policies with MFA requirement found")
            recommendations.append("Create conditional access policies requiring MFA for users")

        return create_response(
            result={
                criteriaKey: is_enabled,
                "policiesTotal": len(policies),
                "policiesWithMFA": len(policies_with_mfa),
                "policiesWithoutMFA": len(policies_without_mfa),
                "conditionalAccessPoliciesWithMFA": policies_with_mfa,
                "conditionalAccessPoliciesWithoutMFA": policies_without_mfa
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"totalPolicies": len(policies), "mfaPolicies": len(policies_with_mfa)}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False, "policiesTotal": 0, "policiesWithMFA": 0, "policiesWithoutMFA": 0},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
