"""
Transformation: isMFAEnforcedForUsers
Vendor: Identity Provider
Category: Identity / MFA

Evaluates the MFA status for users in the IDP.
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
                "transformationId": "isMFAEnforcedForUsers",
                "vendor": "Identity Provider",
                "category": "Identity"
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
                result={"isMFAEnforcedForUsers": False, "totalUsers": 0, "mfaEnrolledUsers": 0},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        # Handle list input (users array)
        users_list = data if isinstance(data, list) else []

        mfa_enrolled = [obj for obj in users_list if 'is_enrolled' in obj and str(obj['is_enrolled']).lower() == "true"]

        total_users = len(users_list)
        mfa_enrolled_count = len(mfa_enrolled)
        is_mfa_enforced = mfa_enrolled_count > 0

        if is_mfa_enforced:
            pass_reasons.append(f"MFA is enabled for {mfa_enrolled_count} of {total_users} users")
        else:
            fail_reasons.append("No users have MFA enabled")
            recommendations.append("Enable MFA for all users to improve security")

        return create_response(
            result={
                "totalUsers": total_users,
                "mfaEnrolledUsers": mfa_enrolled_count,
                "isMFAEnforcedForUsers": is_mfa_enforced
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "totalUsers": total_users,
                "mfaEnrolledUsers": mfa_enrolled_count
            }
        )

    except Exception as e:
        return create_response(
            result={"isMFAEnforcedForUsers": False, "totalUsers": 0, "mfaEnrolledUsers": 0},
            validation={"status": "error", "errors": [str(e)], "warnings": []},
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
