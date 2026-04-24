"""
Transformation: areAdminAccountsSeparate
Vendor: AWS  |  Category: cloudsecurity
Evaluates: Whether dedicated administrative IAM accounts exist separately from standard
user accounts. Examines IAM users returned by ListUsers for naming conventions and
separation of privilege patterns to determine if admin accounts are distinct from
regular operational accounts.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "areAdminAccountsSeparate", "vendor": "AWS", "category": "cloudsecurity"}
        }
    }


def is_admin_user(username):
    if not isinstance(username, str):
        return False
    lower = username.lower()
    admin_tokens = ["admin", "administrator", "superuser", "root", "sysadmin", "devops-admin", "infra-admin", "ops-admin", "privileged"]
    for token in admin_tokens:
        if token in lower:
            return True
    return False


def evaluate(data):
    try:
        users = data.get("Users", [])
        if not isinstance(users, list):
            users = []

        total_users = len(users)
        admin_usernames = []
        standard_usernames = []

        for user in users:
            if not isinstance(user, dict):
                continue
            username = user.get("UserName", "")
            if is_admin_user(username):
                admin_usernames.append(username)
            else:
                standard_usernames.append(username)

        admin_count = len(admin_usernames)
        standard_count = len(standard_usernames)

        has_dedicated_admin_accounts = admin_count > 0
        has_standard_accounts = standard_count > 0
        accounts_are_separate = has_dedicated_admin_accounts and has_standard_accounts

        return {
            "areAdminAccountsSeparate": accounts_are_separate,
            "totalUsers": total_users,
            "adminAccountCount": admin_count,
            "standardAccountCount": standard_count,
            "hasDedicatedAdminAccounts": has_dedicated_admin_accounts,
            "hasStandardAccounts": has_standard_accounts,
            "adminUsernames": admin_usernames
        }
    except Exception as e:
        return {"areAdminAccountsSeparate": False, "error": str(e)}


def transform(input):
    criteriaKey = "areAdminAccountsSeparate"
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
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []
        if result_value:
            pass_reasons.append("Dedicated administrative accounts are present and separate from standard user accounts")
            pass_reasons.append("Admin accounts identified: " + str(extra_fields.get("adminAccountCount", 0)))
            pass_reasons.append("Standard accounts identified: " + str(extra_fields.get("standardAccountCount", 0)))
        else:
            if extra_fields.get("totalUsers", 0) == 0:
                fail_reasons.append("No IAM users were returned by ListUsers — unable to evaluate account separation")
                recommendations.append("Ensure the IAM service account has iam:ListUsers permission")
            elif not extra_fields.get("hasDedicatedAdminAccounts", False):
                fail_reasons.append("No dedicated administrative accounts identified by naming convention")
                recommendations.append("Create dedicated admin IAM accounts with clear naming conventions (e.g. admin-*, *-admin) separate from standard user accounts")
                recommendations.append("Avoid granting administrator-level permissions to general-purpose user accounts")
            else:
                fail_reasons.append("Admin accounts exist but no standard user accounts are present — separation cannot be confirmed")
                recommendations.append("Ensure regular operational tasks use non-admin accounts; reserve admin accounts for privileged operations only")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
        admin_usernames = extra_fields.get("adminUsernames", [])
        if admin_usernames:
            additional_findings.append("Admin-identified accounts: " + ", ".join(admin_usernames))
        additional_findings.append("Total IAM users evaluated: " + str(extra_fields.get("totalUsers", 0)))
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={criteriaKey: result_value, "totalUsers": extra_fields.get("totalUsers", 0), "adminAccountCount": extra_fields.get("adminAccountCount", 0), "standardAccountCount": extra_fields.get("standardAccountCount", 0)}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
