"""
Transformation: isLifeCycleManagementEnabled
Vendor: Duo  |  Category: Multifactor Authentication
Evaluates: Whether user lifecycle management (provisioning and deprovisioning) is evidenced in Duo.
API Method: getUsers
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isLifeCycleManagementEnabled", "vendor": "Duo", "category": "Multifactor Authentication"}
        }
    }


def evaluate(data):
    try:
        users_list = data if isinstance(data, list) else []
        total_users = len(users_list)

        if total_users == 0:
            return {"isLifeCycleManagementEnabled": False, "error": "No user records returned"}

        status_counts = {}
        users_with_groups = 0
        users_with_last_login = 0
        disabled_users = 0
        active_users = 0
        bypassed_users = 0

        for user in users_list:
            if not isinstance(user, dict):
                continue
            status = str(user.get("status", "unknown")).lower()

            if status in status_counts:
                status_counts[status] = status_counts[status] + 1
            else:
                status_counts[status] = 1

            if status == "active":
                active_users = active_users + 1
            elif status == "disabled":
                disabled_users = disabled_users + 1
            elif status == "bypass":
                bypassed_users = bypassed_users + 1

            groups = user.get("groups", [])
            if isinstance(groups, list) and len(groups) > 0:
                users_with_groups = users_with_groups + 1

            last_login = user.get("last_login", None)
            if last_login is not None:
                users_with_last_login = users_with_last_login + 1

        distinct_statuses = len(status_counts)

        # Lifecycle management evidence:
        # 1. Disabled users present => deprovisioning is happening
        # 2. Multiple user statuses => active status management
        # 3. Users assigned to groups => structured provisioning
        has_deprovisioning = disabled_users > 0
        has_status_management = distinct_statuses > 1
        has_group_provisioning = users_with_groups > 0

        lifecycle_enabled = has_deprovisioning or has_status_management or has_group_provisioning

        return {
            "isLifeCycleManagementEnabled": lifecycle_enabled,
            "totalUsers": total_users,
            "activeUsers": active_users,
            "disabledUsers": disabled_users,
            "bypassedUsers": bypassed_users,
            "usersWithGroupAssignment": users_with_groups,
            "distinctUserStatuses": distinct_statuses,
            "statusBreakdown": status_counts,
            "hasDeprovisioning": has_deprovisioning,
            "hasGroupProvisioning": has_group_provisioning
        }
    except Exception as e:
        return {"isLifeCycleManagementEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isLifeCycleManagementEnabled"
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

        total = eval_result.get("totalUsers", 0)
        active = eval_result.get("activeUsers", 0)
        disabled = eval_result.get("disabledUsers", 0)
        bypassed = eval_result.get("bypassedUsers", 0)
        with_groups = eval_result.get("usersWithGroupAssignment", 0)
        has_deprovisioning = eval_result.get("hasDeprovisioning", False)
        has_group_provisioning = eval_result.get("hasGroupProvisioning", False)
        status_breakdown = eval_result.get("statusBreakdown", {})

        if result_value:
            pass_reasons.append("User lifecycle management is evidenced in Duo")
            if has_deprovisioning:
                pass_reasons.append(str(disabled) + " disabled user(s) found, indicating active deprovisioning")
            if has_group_provisioning:
                pass_reasons.append(str(with_groups) + " user(s) assigned to groups, indicating structured provisioning")
            if eval_result.get("distinctUserStatuses", 0) > 1:
                pass_reasons.append("Multiple user statuses detected: " + ", ".join(status_breakdown.keys()))
        else:
            fail_reasons.append("No lifecycle management indicators found: all users are active with no group assignments or disabled accounts")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Implement a user provisioning/deprovisioning process and disable Duo accounts when users leave the organisation")
            recommendations.append("Assign users to groups to enable structured access control and group-level policy enforcement")
            recommendations.append("Consider integrating Duo with an identity provider (IdP) such as Azure AD or Okta for automated lifecycle management")

        if bypassed > 0:
            additional_findings.append(str(bypassed) + " user(s) in bypass mode - review these accounts to ensure bypass is intentional and time-limited")

        return create_response(
            result={
                criteriaKey: result_value,
                "totalUsers": total,
                "activeUsers": active,
                "disabledUsers": disabled,
                "bypassedUsers": bypassed,
                "usersWithGroupAssignment": with_groups,
                "statusBreakdown": status_breakdown
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"totalUsers": total, "activeUsers": active, "disabledUsers": disabled}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
