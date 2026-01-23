"""
Transformation: isMFAEnforcedForUsers
Vendor: Email Security Provider
Category: Identity / Authentication

Evaluates the MFA status for users in the organization.
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
                    recommendations=None, input_summary=None, transformation_errors=None, api_errors=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "validationStatus": validation.get("status", "unknown"),
            "validationErrors": validation.get("errors", []),
            "validationWarnings": validation.get("warnings", []),
            "transformationErrors": transformation_errors or [],

            "apiErrors": api_errors or [],
            "passReasons": pass_reasons or [],

            "failReasons": fail_reasons or [],
            "recommendations": recommendations or [],
            "inputSummary": input_summary or {},
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "isMFAEnforcedForUsers",
                "vendor": "Email Security Provider",
                "category": "Identity"
            }
        }
    }


def transform(input):
    criteriaKey = "isMFAEnforcedForUsers"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: False, "totalUsers": 0, "mfaEnrolledUsers": 0},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        isMFAEnforcedForUsers = False
        total_users = 0
        mfa_enrolled_users = 0

        if isinstance(data, dict):
            # Check for direct MFA flag
            if 'isMFAEnforcedForUsers' in data:
                isMFAEnforcedForUsers = data['isMFAEnforcedForUsers']

            # Check rawResponse for user details
            raw_data = data.get('rawResponse', data)

            if isinstance(raw_data, dict) and 'users' in raw_data:
                users = raw_data['users']
                if isinstance(users, list):
                    total_users = len(users)
                    mfa_enrolled = [obj for obj in users if 'isEnforcedIn2Sv' in obj and str(obj['isEnforcedIn2Sv']).lower() == "true"]
                    mfa_enrolled_users = len(mfa_enrolled)
                    isMFAEnforcedForUsers = mfa_enrolled_users > 0

        if isMFAEnforcedForUsers:
            if total_users > 0:
                percentage = round((mfa_enrolled_users / total_users) * 100)
                pass_reasons.append(f"MFA enforced for {mfa_enrolled_users}/{total_users} users ({percentage}%)")
            else:
                pass_reasons.append("MFA enforcement is enabled")
        else:
            fail_reasons.append("MFA is not enforced for users")
            recommendations.append("Enable MFA enforcement (2-Step Verification) for all users")

        return create_response(
            result={
                criteriaKey: isMFAEnforcedForUsers,
                "totalUsers": total_users,
                "mfaEnrolledUsers": mfa_enrolled_users
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "totalUsers": total_users,
                "mfaEnrolledUsers": mfa_enrolled_users
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False, "totalUsers": 0, "mfaEnrolledUsers": 0},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
