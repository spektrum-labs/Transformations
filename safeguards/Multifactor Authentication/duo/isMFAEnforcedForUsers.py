"""
Transformation: isMFAEnforcedForUsers
Vendor: Duo  |  Category: Multifactor Authentication
Evaluates: Whether all active users have MFA enrolled in Duo.
API Method: getUsers (via getEstateMFAStatus)
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isMFAEnforcedForUsers", "vendor": "Duo", "category": "Multifactor Authentication"}
        }
    }


def evaluate(data):
    try:
        users_list = data if isinstance(data, list) else []
        total_users = len(users_list)
        mfa_enrolled_count = 0
        offending_users = []

        for user in users_list:
            is_enrolled = user.get("is_enrolled", False)
            status = str(user.get("status", "")).lower()
            if str(is_enrolled).lower() == "true" or is_enrolled is True:
                mfa_enrolled_count = mfa_enrolled_count + 1
            else:
                if status == "active":
                    offending_users = offending_users + [{
                        "username": user.get("username", ""),
                        "email": user.get("email", ""),
                        "status": user.get("status", "")
                    }]

        is_enforced = len(offending_users) == 0
        score = 0
        if total_users > 0:
            score = int((mfa_enrolled_count * 100) / total_users)

        return {
            "isMFAEnforcedForUsers": is_enforced,
            "totalUsers": total_users,
            "mfaEnrolledUsers": mfa_enrolled_count,
            "nonCompliantUsers": len(offending_users),
            "scoreInPercentage": score,
            "offendingUsers": offending_users
        }
    except Exception as e:
        return {"isMFAEnforcedForUsers": False, "error": str(e)}


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
                result={criteriaKey: False, "totalUsers": 0, "mfaEnrolledUsers": 0, "offendingUsers": []},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        pass_reasons = []
        fail_reasons = []
        recommendations = []

        total = eval_result.get("totalUsers", 0)
        enrolled = eval_result.get("mfaEnrolledUsers", 0)
        non_compliant = eval_result.get("nonCompliantUsers", 0)
        score = eval_result.get("scoreInPercentage", 0)

        if result_value:
            pass_reasons.append("All active Duo users have MFA enrolled")
            pass_reasons.append("Enrolled users: " + str(enrolled) + " of " + str(total) + " (" + str(score) + "%)")
        else:
            fail_reasons.append(str(non_compliant) + " active user(s) do not have MFA enrolled")
            fail_reasons.append("MFA enrollment score: " + str(score) + "%")
            recommendations.append("Enroll all active users in Duo MFA to prevent account takeover")
            recommendations.append("Consider enabling Duo's new user enrollment policy to require MFA at first login")

        return create_response(
            result={
                criteriaKey: result_value,
                "totalUsers": total,
                "mfaEnrolledUsers": enrolled,
                "nonCompliantUsers": non_compliant,
                "scoreInPercentage": score,
                "offendingUsers": eval_result.get("offendingUsers", [])
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"totalUsers": total, "mfaEnrolledUsers": enrolled, "nonCompliantUsers": non_compliant}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False, "totalUsers": 0, "mfaEnrolledUsers": 0, "offendingUsers": []},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
