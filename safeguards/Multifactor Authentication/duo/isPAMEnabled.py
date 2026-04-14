"""
Transformation: isPAMEnabled
Vendor: Duo  |  Category: Multifactor Authentication
Evaluates: Whether Privileged Access Management is implemented by verifying admin account controls in Duo.
API Method: getAdmins
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isPAMEnabled", "vendor": "Duo", "category": "Multifactor Authentication"}
        }
    }


def evaluate(data):
    try:
        admins_list = data if isinstance(data, list) else []
        total_admins = len(admins_list)

        if total_admins == 0:
            return {"isPAMEnabled": False, "error": "No admin records returned"}

        # Duo admin roles ordered from most to least privileged
        privileged_roles = ["Owner", "Administrator"]
        restricted_roles = ["Application Manager", "User Manager", "Security Analyst", "Help Desk", "Billing", "Read-only"]

        owner_count = 0
        restricted_role_count = 0
        admins_with_phone = 0
        role_distribution = {}
        overprivileged_admins = []

        for admin in admins_list:
            if not isinstance(admin, dict):
                continue
            role = admin.get("role", "Unknown")
            email = admin.get("email", admin.get("name", "unknown"))
            phone = admin.get("phone", "")

            if role in role_distribution:
                role_distribution[role] = role_distribution[role] + 1
            else:
                role_distribution[role] = 1

            if str(role).lower() == "owner":
                owner_count = owner_count + 1
                overprivileged_admins = overprivileged_admins + [email]

            if role in restricted_roles:
                restricted_role_count = restricted_role_count + 1

            if phone:
                admins_with_phone = admins_with_phone + 1

        # PAM indicators:
        # 1. Least privilege: not all admins are Owners
        # 2. Restricted/scoped roles are in use
        # 3. Owner count is minimised (<=2 for reasonable org)
        all_owners = (owner_count == total_admins)
        has_least_privilege = not all_owners and restricted_role_count > 0
        owner_count_acceptable = owner_count <= 2

        pam_enabled = has_least_privilege or (total_admins > 0 and owner_count_acceptable)

        return {
            "isPAMEnabled": pam_enabled,
            "totalAdmins": total_admins,
            "ownerCount": owner_count,
            "restrictedRoleAdmins": restricted_role_count,
            "hasLeastPrivilege": has_least_privilege,
            "ownerCountAcceptable": owner_count_acceptable,
            "roleDistribution": role_distribution,
            "overprivilegedAdmins": overprivileged_admins
        }
    except Exception as e:
        return {"isPAMEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isPAMEnabled"
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
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        total = eval_result.get("totalAdmins", 0)
        owner_count = eval_result.get("ownerCount", 0)
        restricted_count = eval_result.get("restrictedRoleAdmins", 0)
        has_least_privilege = eval_result.get("hasLeastPrivilege", False)
        owner_acceptable = eval_result.get("ownerCountAcceptable", False)
        role_distribution = eval_result.get("roleDistribution", {})
        overprivileged = eval_result.get("overprivilegedAdmins", [])

        if result_value:
            pass_reasons.append("Privileged access management controls are in place for Duo admin accounts")
            if has_least_privilege:
                pass_reasons.append(str(restricted_count) + " admin(s) assigned restricted roles, enforcing least privilege")
            if owner_acceptable:
                pass_reasons.append("Owner-level admin count is acceptable: " + str(owner_count))
            role_summary = ", ".join([r + ": " + str(role_distribution[r]) for r in role_distribution])
            pass_reasons.append("Role distribution: " + role_summary)
        else:
            fail_reasons.append("PAM controls are insufficient: all " + str(total) + " admin(s) hold Owner-level privileges")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Apply least-privilege principles by assigning scoped admin roles (Help Desk, User Manager, Read-only) instead of Owner")
            recommendations.append("Limit Owner-level access to no more than 2 administrators")
            recommendations.append("Review all admin accounts and remove unnecessary privileged access")

        if owner_count > 2:
            additional_findings.append(str(owner_count) + " Owner accounts detected. Best practice recommends no more than 2. Accounts: " + ", ".join(overprivileged))

        return create_response(
            result={
                criteriaKey: result_value,
                "totalAdmins": total,
                "ownerCount": owner_count,
                "restrictedRoleAdmins": restricted_count,
                "hasLeastPrivilege": has_least_privilege,
                "roleDistribution": role_distribution
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"totalAdmins": total, "ownerCount": owner_count, "restrictedRoleAdmins": restricted_count}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
