"""
Transformation: isMFAEnforcedForAdminAccess
Vendor: Google  |  Category: IAM
Evaluates: Verify that MFA (2-Step Verification) is enforced for all administrator accounts
by checking the isEnforcedIn2Sv field on admin users returned by the Directory API
with query=isAdmin=true. Passes if all admin users have isEnforcedIn2Sv=true.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isMFAEnforcedForAdminAccess", "vendor": "Google", "category": "IAM"}
        }
    }


def evaluate(data):
    try:
        users = data.get("users", [])
        if not isinstance(users, list):
            users = []

        admin_users = [u for u in users if u.get("isAdmin", False) or u.get("isDelegatedAdmin", False)]

        if not admin_users:
            admin_users = users

        total_admins = len(admin_users)

        if total_admins == 0:
            return {
                "isMFAEnforcedForAdminAccess": False,
                "totalAdminUsers": 0,
                "enforcedCount": 0,
                "notEnforcedCount": 0,
                "notEnforcedAdmins": [],
                "notEnrolledAdmins": [],
                "error": "No admin users found in API response"
            }

        enforced_count = 0
        not_enforced = []
        not_enrolled = []

        for user in admin_users:
            email = user.get("primaryEmail", user.get("email", "unknown"))
            enforced = user.get("isEnforcedIn2Sv", False)
            enrolled = user.get("isEnrolledIn2Sv", False)
            if enforced:
                enforced_count = enforced_count + 1
            else:
                not_enforced.append(email)
            if not enrolled:
                not_enrolled.append(email)

        not_enforced_count = total_admins - enforced_count
        all_enforced = enforced_count == total_admins

        return {
            "isMFAEnforcedForAdminAccess": all_enforced,
            "totalAdminUsers": total_admins,
            "enforcedCount": enforced_count,
            "notEnforcedCount": not_enforced_count,
            "notEnforcedAdmins": not_enforced,
            "notEnrolledAdmins": not_enrolled
        }
    except Exception as e:
        return {"isMFAEnforcedForAdminAccess": False, "error": str(e)}


def transform(input):
    criteriaKey = "isMFAEnforcedForAdminAccess"
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

        total_admins = eval_result.get("totalAdminUsers", 0)
        enforced_count = eval_result.get("enforcedCount", 0)
        not_enforced_count = eval_result.get("notEnforcedCount", 0)
        not_enforced_admins = eval_result.get("notEnforcedAdmins", [])
        not_enrolled_admins = eval_result.get("notEnrolledAdmins", [])

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        if result_value:
            pass_reasons.append(
                "2-Step Verification is enforced for all " + str(total_admins) +
                " administrator account(s)"
            )
        else:
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            else:
                fail_reasons.append(
                    str(not_enforced_count) + " of " + str(total_admins) +
                    " admin account(s) do not have 2-Step Verification enforced: " +
                    ", ".join(not_enforced_admins[:10])
                )
            recommendations.append(
                "Enforce 2-Step Verification for all administrator accounts in the Google Workspace Admin Console under Security > 2-Step Verification > Enforcement"
            )
            recommendations.append(
                "Set enforcement to 'On' specifically for the Admins organizational unit to ensure all privileged accounts require 2SV"
            )

        if len(not_enrolled_admins) > 0:
            additional_findings.append(
                str(len(not_enrolled_admins)) + " admin(s) are not yet enrolled in 2SV: " +
                ", ".join(not_enrolled_admins[:10])
            )

        extra_fields = {
            "totalAdminUsers": total_admins,
            "enforcedCount": enforced_count,
            "notEnforcedCount": not_enforced_count,
            "notEnforcedAdmins": not_enforced_admins,
            "notEnrolledAdmins": not_enrolled_admins
        }

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"totalAdminUsers": total_admins, "enforcedCount": enforced_count}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
