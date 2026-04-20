"""
Transformation: confirmPasswordPolicyEnforced
Vendor: Google  |  Category: IAM
Evaluates: Examines user objects from the Directory API for password policy enforcement signals,
including the changePasswordAtNextLogin flag and password-related attributes in the full
projection user response.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "confirmPasswordPolicyEnforced", "vendor": "Google", "category": "IAM"}
        }
    }


def evaluate(data):
    try:
        users = data.get("users", [])
        if not isinstance(users, list):
            users = []

        total_users = len(users)
        if total_users == 0:
            return {
                "confirmPasswordPolicyEnforced": False,
                "totalUsers": 0,
                "totalActiveUsers": 0,
                "compliantUserCount": 0,
                "pendingPasswordChangeCount": 0,
                "weakPasswordCount": 0,
                "compliancePercentage": 0,
                "error": "No user data returned from the Directory API"
            }

        active_users = [u for u in users if isinstance(u, dict) and not u.get("suspended", False)]
        total_active = len(active_users)

        if total_active == 0:
            return {
                "confirmPasswordPolicyEnforced": False,
                "totalUsers": total_users,
                "totalActiveUsers": 0,
                "compliantUserCount": 0,
                "pendingPasswordChangeCount": 0,
                "weakPasswordCount": 0,
                "compliancePercentage": 0,
                "error": "All users are suspended; cannot evaluate password policy compliance"
            }

        pending_change_count = 0
        compliant_count = 0
        weak_password_count = 0

        for user in active_users:
            change_required = user.get("changePasswordAtNextLogin", False)
            if change_required:
                pending_change_count = pending_change_count + 1
            else:
                compliant_count = compliant_count + 1
            pwd_strength = user.get("passwordStrength", "")
            if isinstance(pwd_strength, str) and pwd_strength.upper() == "WEAK":
                weak_password_count = weak_password_count + 1

        compliance_ratio = compliant_count / total_active
        compliance_pct = round(compliance_ratio * 100, 1)

        # Policy considered enforced when >= 80% of active users have set their password
        # (changePasswordAtNextLogin: false) and no weak passwords are detected
        password_policy_enforced = compliance_ratio >= 0.8 and weak_password_count == 0

        return {
            "confirmPasswordPolicyEnforced": password_policy_enforced,
            "totalUsers": total_users,
            "totalActiveUsers": total_active,
            "compliantUserCount": compliant_count,
            "pendingPasswordChangeCount": pending_change_count,
            "weakPasswordCount": weak_password_count,
            "compliancePercentage": compliance_pct
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
        extra_fields = {k: eval_result[k] for k in eval_result if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []
        if result_value:
            compliance_pct = eval_result.get("compliancePercentage", 0)
            compliant = eval_result.get("compliantUserCount", 0)
            total_active = eval_result.get("totalActiveUsers", 0)
            pass_reasons.append("Password policy is enforced; " + str(compliance_pct) + "% of active users have set compliant passwords")
            pass_reasons.append("Compliant users: " + str(compliant) + " of " + str(total_active) + " active users")
            if eval_result.get("weakPasswordCount", 0) == 0:
                pass_reasons.append("No weak passwords detected among active users")
        else:
            total_active = eval_result.get("totalActiveUsers", 0)
            if total_active == 0:
                fail_reasons.append("No active user data available to evaluate password policy")
                recommendations.append("Verify the Google Directory API returns user data with the 'full' projection parameter")
            else:
                compliance_pct = eval_result.get("compliancePercentage", 0)
                pending = eval_result.get("pendingPasswordChangeCount", 0)
                weak = eval_result.get("weakPasswordCount", 0)
                if compliance_pct < 80:
                    fail_reasons.append(
                        "Only " + str(compliance_pct) + "% of active users have compliant passwords; "
                        + str(pending) + " user(s) have a pending required password change"
                    )
                    recommendations.append("Follow up with users who have not yet changed their password and ensure password policy is configured in Google Workspace Admin Console under Security > Password Management")
                if weak > 0:
                    fail_reasons.append(str(weak) + " active user(s) have weak passwords detected")
                    recommendations.append("Enforce minimum password strength requirements in Google Workspace Admin Console under Security > Password Management")
            if "error" in eval_result:
                fail_reasons.append("Evaluation error: " + eval_result["error"])
        pending = eval_result.get("pendingPasswordChangeCount", 0)
        if pending > 0:
            additional_findings.append(str(pending) + " active user(s) are currently flagged to change their password at next login")
        weak = eval_result.get("weakPasswordCount", 0)
        if weak > 0:
            additional_findings.append(str(weak) + " active user(s) have a weak password strength detected via the Directory API")
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
            input_summary={
                "totalUsers": eval_result.get("totalUsers", 0),
                "totalActiveUsers": eval_result.get("totalActiveUsers", 0),
                "compliantUserCount": eval_result.get("compliantUserCount", 0),
                "pendingPasswordChangeCount": eval_result.get("pendingPasswordChangeCount", 0),
                "compliancePercentage": eval_result.get("compliancePercentage", 0)
            }
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False}, validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)], fail_reasons=["Transformation error: " + str(e)])
