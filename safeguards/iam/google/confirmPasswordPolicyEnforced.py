"""
Transformation: confirmPasswordPolicyEnforced
Vendor: Google  |  Category: iam
Evaluates: Examines user records returned from the Directory API (projection=full) to
assess password policy enforcement. Checks the changePasswordAtNextLogin field on each
active user. Passes when all active, non-suspended users have a confirmed compliant
password already set (changePasswordAtNextLogin is false for all). Reports compliance
score and count of users with pending forced password changes.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for i in range(3):
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "confirmPasswordPolicyEnforced", "vendor": "Google", "category": "iam"}
        }
    }


def evaluate(data):
    try:
        users = data.get("users", [])
        if not users:
            return {
                "confirmPasswordPolicyEnforced": False,
                "totalUsers": 0,
                "totalActiveUsers": 0,
                "usersWithPendingPasswordChange": 0,
                "compliantUsers": 0,
                "scoreInPercentage": 0.0,
                "pendingChangeEmails": [],
                "error": "No user data available in response"
            }

        total_users = len(users)
        active_users = [u for u in users if not u.get("suspended", False)]
        total_active = len(active_users)

        if total_active == 0:
            return {
                "confirmPasswordPolicyEnforced": False,
                "totalUsers": total_users,
                "totalActiveUsers": 0,
                "usersWithPendingPasswordChange": 0,
                "compliantUsers": 0,
                "scoreInPercentage": 0.0,
                "pendingChangeEmails": [],
                "error": "No active (non-suspended) users found"
            }

        pending_users = [u for u in active_users if u.get("changePasswordAtNextLogin", False)]
        pending_count = len(pending_users)
        compliant_count = total_active - pending_count

        score = (compliant_count * 100.0) / total_active

        pending_emails = []
        for u in pending_users:
            email = u.get("primaryEmail", "unknown")
            pending_emails.append(email)

        is_enforced = pending_count == 0

        return {
            "confirmPasswordPolicyEnforced": is_enforced,
            "totalUsers": total_users,
            "totalActiveUsers": total_active,
            "usersWithPendingPasswordChange": pending_count,
            "compliantUsers": compliant_count,
            "scoreInPercentage": round(score, 2),
            "pendingChangeEmails": pending_emails
        }
    except Exception as e:
        return {"confirmPasswordPolicyEnforced": False, "error": str(e)}


def transform(input):
    criteriaKey = "confirmPasswordPolicyEnforced"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(result={criteriaKey: False}, validation=validation, fail_reasons=["Input validation failed"])
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)

        extra_fields = {}
        for k in eval_result:
            if k != criteriaKey and k != "error":
                extra_fields[k] = eval_result[k]

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        total_active = eval_result.get("totalActiveUsers", 0)
        pending_count = eval_result.get("usersWithPendingPasswordChange", 0)
        compliant_count = eval_result.get("compliantUsers", 0)
        score = eval_result.get("scoreInPercentage", 0.0)
        pending_emails = eval_result.get("pendingChangeEmails", [])

        if result_value:
            pass_reasons.append("All " + str(total_active) + " active users have confirmed compliant passwords set (changePasswordAtNextLogin is false for all)")
            pass_reasons.append("Password policy compliance score: " + str(score) + "%")
        else:
            fail_reasons.append(str(pending_count) + " active user(s) have a forced password change pending (changePasswordAtNextLogin is true)")
            fail_reasons.append("Password policy compliance score: " + str(score) + "% (" + str(compliant_count) + " of " + str(total_active) + " active users compliant)")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Ensure all active users have reset their passwords to meet the organization password policy")
            recommendations.append("Review users with pending password changes: " + ", ".join(pending_emails[:10]))
            if len(pending_emails) > 10:
                recommendations.append("... and " + str(len(pending_emails) - 10) + " more users")

        additional_findings.append("Total users in directory: " + str(eval_result.get("totalUsers", 0)))
        additional_findings.append("Active (non-suspended) users evaluated: " + str(total_active))

        result_dict = {criteriaKey: result_value}
        for k in extra_fields:
            result_dict[k] = extra_fields[k]

        return create_response(
            result=result_dict,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"totalUsers": eval_result.get("totalUsers", 0), "totalActiveUsers": total_active, "pendingPasswordChange": pending_count}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
