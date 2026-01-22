"""
Transformation: isMFAEnforcedForSecurityAdminAccess
Vendor: Microsoft
Category: Identity / MFA

Evaluates if MFA is enforced for security administrator role access via conditional access policies.
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
                "transformationId": "isMFAEnforcedForSecurityAdminAccess",
                "vendor": "Microsoft",
                "category": "Identity"
            }
        }
    }


def transform(input):
    criteriaKey = "isMFAEnforcedForSecurityAdminAccess"

    # Security Administrator role GUID
    endpoint_security_roles = [
        "62e90394-69f5-4237-9190-012177145e10"
    ]

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: False, "policyCountTotal": 0, "policyCountforSecurityRole": 0, "policyCountNotForSecurityRole": 0},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        policies = data.get('value', [])
        policy_count_total = 0
        policies_for_security_role = []
        policies_not_for_security_role = []

        for policy in policies:
            roles = policy.get("conditions", {}).get("users", {}).get("includeRoles", [])
            grant_controls = policy.get("grantControls", {}).get("builtInControls", [])

            if any(role in endpoint_security_roles for role in roles):
                policies_for_security_role.append(policy.get("displayName"))
            else:
                policies_not_for_security_role.append(policy.get("displayName"))
            policy_count_total += 1

        is_enforced = len(policies_for_security_role) > 0

        if is_enforced:
            pass_reasons.append(f"MFA enforced for security admin access via {len(policies_for_security_role)} policy(ies): {', '.join(policies_for_security_role[:3])}")
        else:
            fail_reasons.append("No conditional access policies found enforcing MFA for security administrator role")
            recommendations.append("Create a conditional access policy requiring MFA for Security Administrator role")

        return create_response(
            result={
                criteriaKey: is_enforced,
                "policyCountTotal": policy_count_total,
                "policyCountforSecurityRole": len(policies_for_security_role),
                "policyCountNotForSecurityRole": len(policies_not_for_security_role)
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"totalPolicies": policy_count_total, "policiesForSecurityRole": len(policies_for_security_role)}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False, "policyCountTotal": 0, "policyCountforSecurityRole": 0, "policyCountNotForSecurityRole": 0},
            validation={"status": "error", "errors": [str(e)], "warnings": []},
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
