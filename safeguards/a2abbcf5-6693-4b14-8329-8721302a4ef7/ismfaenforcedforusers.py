"""
Transformation: isMFAEnforcedForUsers
Vendor: Identity Provider
Category: Identity / MFA

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
                result={"isMFAEnforcedForUsers": False, "totalUsers": 0, "mfaEnrolledUsers": 0, "offendingUsers": []},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        total_users = 0
        mfa_enrolled_users = 0
        offending_users = []
        is_mfa_enforced = True

        # Get metadata for total users count
        if isinstance(input, dict) and 'metadata' in input:
            metadata = input['metadata']
            if 'total_objects' in metadata:
                try:
                    total_users = int(metadata['total_objects'])
                except:
                    total_users = metadata['total_objects']

        # Handle list input (users array)
        users_list = data if isinstance(data, list) else []

        # NO USER LIST MEANS NOTHING WAS MEASURED, NOT THAT EVERYONE IS ENROLLED.
        # `is_mfa_enforced` is initialised True and only a user with is_enrolled false and
        # status active ever flips it, so an absent, empty or non-list body left the
        # optimistic initial value untouched and reported "MFA policy configured (no users
        # currently enrolled)". Measured 2026-09-21: transform(None) returned
        # isMFAEnforcedForUsers true. "Every active user is enrolled" is a statement about
        # a roster that was READ; with no roster there is no such statement to make, and
        # an unenrolled user is exactly what an unread roster hides.
        if not isinstance(data, list):
            return create_response(
                result={"isMFAEnforcedForUsers": False, "totalUsers": total_users,
                        "mfaEnrolledUsers": 0, "offendingUsers": []},
                validation=validation,
                fail_reasons=[
                    "No user list was returned (the body was absent, empty, an error "
                    "response, or not an array), so MFA enrolment could not be measured "
                    "for any user. This is not a finding that MFA is unenforced -- it is "
                    "the absence of a reading, and it must not be recorded as enforcement."
                ],
                recommendations=[
                    "Confirm the identity provider credential is valid and the user list "
                    "call returned a 2xx array before reading this criterion."
                ],
                input_summary={"userListReturned": False}
            )

        for user in users_list:
            if 'is_enrolled' in user:
                if str(user['is_enrolled']).lower() == "true":
                    mfa_enrolled_users = mfa_enrolled_users + 1
                else:
                    if 'status' in user:
                        if str(user['status']).lower() == "active":
                            offending_users = offending_users + [user]
                            is_mfa_enforced = False

        if is_mfa_enforced:
            if mfa_enrolled_users > 0:
                pass_reasons = pass_reasons + [f"MFA enforced: {mfa_enrolled_users} users enrolled"]
            else:
                pass_reasons = pass_reasons + ["MFA policy configured (no users currently enrolled)"]
        else:
            fail_reasons = fail_reasons + [f"{len(offending_users)} active users do not have MFA enabled"]
            recommendations = recommendations + ["Enable MFA for all active users to improve security"]

        return create_response(
            result={
                "totalUsers": total_users if total_users > 0 else len(users_list),
                "mfaEnrolledUsers": mfa_enrolled_users,
                "isMFAEnforcedForUsers": is_mfa_enforced,
                "offendingUsers": offending_users
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "totalUsers": total_users if total_users > 0 else len(users_list),
                "mfaEnrolledUsers": mfa_enrolled_users,
                "offendingUsersCount": len(offending_users)
            }
        )

    except Exception as e:
        return create_response(
            result={"isMFAEnforcedForUsers": False, "totalUsers": 0, "mfaEnrolledUsers": 0, "offendingUsers": []},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
