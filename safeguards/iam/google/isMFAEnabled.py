"""
Transformation: isMFAEnabled
Vendor: Google  |  Category: IAM
Evaluates: Check if MFA (2-Step Verification) is enabled in the Google Workspace domain
by inspecting the isEnrolledIn2Sv field on user objects returned by the Directory API.
Passes if at least one user is enrolled, indicating 2SV is available and in use.
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
                    recommendations=None, input_summary=None, transformation_errors=None,
                    api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isMFAEnabled", "vendor": "Google", "category": "IAM"}
        }
    }


def evaluate(data):
    try:
        users = data.get("users", [])
        if not isinstance(users, list):
            users = []

        total_users = len(users)
        enrolled_count = 0
        not_enrolled = []

        for user in users:
            email = user.get("primaryEmail", user.get("email", "unknown"))
            enrolled = user.get("isEnrolledIn2Sv", False)
            if enrolled:
                enrolled_count = enrolled_count + 1
            else:
                not_enrolled.append(email)

        if total_users == 0:
            return {
                "isMFAEnabled": False,
                "totalUsers": 0,
                "enrolledCount": 0,
                "notEnrolledCount": 0,
                "enrollmentPercentage": 0,
                "notEnrolledUsers": [],
                "error": "No users found in API response"
            }

        not_enrolled_count = total_users - enrolled_count
        percentage = (enrolled_count * 100) // total_users

        mfa_enabled = enrolled_count > 0

        return {
            "isMFAEnabled": mfa_enabled,
            "totalUsers": total_users,
            "enrolledCount": enrolled_count,
            "notEnrolledCount": not_enrolled_count,
            "enrollmentPercentage": percentage,
            "notEnrolledUsers": not_enrolled
        }
    except Exception as e:
        return {"isMFAEnabled": False, "error": str(e)}


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
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)

        total_users = eval_result.get("totalUsers", 0)
        enrolled_count = eval_result.get("enrolledCount", 0)
        not_enrolled_count = eval_result.get("notEnrolledCount", 0)
        enrollment_percentage = eval_result.get("enrollmentPercentage", 0)
        not_enrolled_users = eval_result.get("notEnrolledUsers", [])

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        if result_value:
            pass_reasons.append(
                "MFA (2-Step Verification) is enabled: " + str(enrolled_count) +
                " of " + str(total_users) + " users are enrolled (" +
                str(enrollment_percentage) + "%)"
            )
        else:
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            else:
                fail_reasons.append(
                    "No users are enrolled in 2-Step Verification out of " +
                    str(total_users) + " total users"
                )
            recommendations.append(
                "Enable and enforce 2-Step Verification (2SV) for all users in the Google Workspace Admin Console under Security > 2-Step Verification"
            )

        if not_enrolled_count > 0:
            additional_findings.append(
                str(not_enrolled_count) + " user(s) are not enrolled in 2SV"
            )

        extra_fields = {
            "totalUsers": total_users,
            "enrolledCount": enrolled_count,
            "notEnrolledCount": not_enrolled_count,
            "enrollmentPercentage": enrollment_percentage,
            "notEnrolledUsers": not_enrolled_users
        }

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"totalUsers": total_users, "enrolledCount": enrolled_count}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
