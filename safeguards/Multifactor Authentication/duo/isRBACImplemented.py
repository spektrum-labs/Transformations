"""
Transformation: isRBACImplemented
Vendor: Duo  |  Category: Multifactor Authentication
Evaluates: Whether Role-Based Access Control is implemented via differentiated admin roles and user groups.
API Method: getAdmins (merge:true) + getGroups (merge:true)
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isRBACImplemented", "vendor": "Duo", "category": "Multifactor Authentication"}
        }
    }


def evaluate(data):
    try:
        admins = []
        groups = []

        if isinstance(data, dict):
            if "getAdmins" in data:
                admins = data["getAdmins"] if isinstance(data["getAdmins"], list) else []
            if "getGroups" in data:
                groups = data["getGroups"] if isinstance(data["getGroups"], list) else []
            # Flat list fallback: if data is a list of admins directly
        elif isinstance(data, list):
            admins = data

        total_admins = len(admins)
        total_groups = len(groups)

        # Collect distinct admin roles
        role_set = []
        role_counts = {}
        all_owner = True

        for admin in admins:
            if not isinstance(admin, dict):
                continue
            role = admin.get("role", "Unknown")
            if role not in role_set:
                role_set = role_set + [role]
            if role in role_counts:
                role_counts[role] = role_counts[role] + 1
            else:
                role_counts[role] = 1
            if str(role).lower() != "owner":
                all_owner = False

        distinct_roles = len(role_set)

        # RBAC criteria:
        # 1. More than one distinct admin role exists (role differentiation)
        # 2. At least one group exists for user-level organisation
        has_role_differentiation = distinct_roles > 1 or (total_admins > 0 and not all_owner)
        has_groups = total_groups > 0

        rbac_implemented = has_role_differentiation or has_groups

        # Identify any admins with Owner-level full access
        owner_admins = [a.get("email", a.get("name", "unknown")) for a in admins if isinstance(a, dict) and str(a.get("role", "")).lower() == "owner"]

        return {
            "isRBACImplemented": rbac_implemented,
            "totalAdmins": total_admins,
            "totalGroups": total_groups,
            "distinctAdminRoles": distinct_roles,
            "adminRoles": role_set,
            "adminRoleCounts": role_counts,
            "hasRoleDifferentiation": has_role_differentiation,
            "hasGroups": has_groups,
            "ownerAdmins": owner_admins
        }
    except Exception as e:
        return {"isRBACImplemented": False, "error": str(e)}


def transform(input):
    criteriaKey = "isRBACImplemented"
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

        total_admins = eval_result.get("totalAdmins", 0)
        total_groups = eval_result.get("totalGroups", 0)
        distinct_roles = eval_result.get("distinctAdminRoles", 0)
        admin_roles = eval_result.get("adminRoles", [])
        has_role_differentiation = eval_result.get("hasRoleDifferentiation", False)
        has_groups = eval_result.get("hasGroups", False)
        owner_admins = eval_result.get("ownerAdmins", [])

        if result_value:
            pass_reasons.append("RBAC is implemented in Duo")
            if has_role_differentiation:
                pass_reasons.append("Admin role differentiation detected: " + str(distinct_roles) + " distinct roles across " + str(total_admins) + " admin(s)")
                pass_reasons.append("Roles in use: " + ", ".join(admin_roles))
            if has_groups:
                pass_reasons.append(str(total_groups) + " user group(s) configured for structured access control")
        else:
            fail_reasons.append("RBAC indicators not found: no role differentiation and no user groups detected")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Assign differentiated admin roles (e.g. Help Desk, User Manager, Read-only) instead of granting Owner to all admins")
            recommendations.append("Create user groups in Duo to segment users and apply group-level policies")

        if owner_admins:
            msg = str(len(owner_admins)) + " admin(s) have full Owner-level access: " + ", ".join(owner_admins)
            additional_findings.append(msg)

        return create_response(
            result={
                criteriaKey: result_value,
                "totalAdmins": total_admins,
                "totalGroups": total_groups,
                "distinctAdminRoles": distinct_roles,
                "adminRoles": admin_roles,
                "hasRoleDifferentiation": has_role_differentiation,
                "hasGroups": has_groups
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"totalAdmins": total_admins, "totalGroups": total_groups, "distinctAdminRoles": distinct_roles}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
