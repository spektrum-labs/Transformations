"""Transformation: isRBACEnforced"""
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
                if key in data and isinstance(data.get(key), (dict, list)):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped or not isinstance(data, dict):
                break
    validation = {
        "status": "unknown",
        "errors": [],
        "warnings": ["Legacy input format - no schema validation performed"],
    }
    return data, validation


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None,
                    transformation_errors=None, api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    transform_err_list = transformation_errors or []
    data_collection_status = "error" if api_err_list else "success"
    transformation_status = "error" if transform_err_list else "success"
    response_metadata = {
        "evaluatedAt": datetime.utcnow().isoformat() + "Z",
        "schemaVersion": "2.0",
    }
    if metadata:
        response_metadata.update(metadata)
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": data_collection_status, "errors": api_err_list},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": transformation_status,
                "errors": transform_err_list,
                "inputSummary": input_summary or {},
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or [],
            },
            "metadata": response_metadata,
        },
    }


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    if isinstance(data, list):
        users = data
    elif isinstance(data, dict):
        users = data.get("data") or []
        if not isinstance(users, list):
            users = []
    else:
        users = []

    role_counts = {}
    total_users = 0
    for u in users:
        if not isinstance(u, dict):
            continue
        total_users = total_users + 1
        role = u.get("role") or "unknown"
        role_counts[role] = role_counts.get(role, 0) + 1

    distinct_roles = list(role_counts.keys())
    num_distinct_roles = len(distinct_roles)

    # RBAC is considered enforced when members are assigned differentiated
    # roles (more than one distinct role value present among org members),
    # rather than every member defaulting to a single flat privilege level.
    # This is derived purely from the observed role distribution, including
    # the case of zero/one members returning naturally-false results.
    is_enforced = num_distinct_roles > 1

    role_summary = ", ".join([f"{role}={count}" for role, count in role_counts.items()])

    if total_users == 0:
        pass_reasons = []
        fail_reasons = ["listOrganizationUsers returned zero members, so no role field values were available to assess differentiation."]
        recommendations = ["Verify the Admin API key has permission to list organization users, or confirm the organization has members."]
    elif is_enforced:
        pass_reasons = [
            f"Organization has {total_users} members across {num_distinct_roles} distinct roles ({role_summary}), showing differentiated privilege levels rather than a single flat role."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"All {total_users} organization members share a single role ({role_summary}). No role differentiation was found among {', '.join(distinct_roles) if distinct_roles else 'members'}."
        ]
        recommendations = [
            "Assign differentiated roles (owner, admin, developer, billing, user, claude_code_user) or custom roles to organization members instead of a single flat privilege level."
        ]

    return create_response(
        result={
            "isRBACEnforced": is_enforced,
            "totalUsers": total_users,
            "distinctRoleCount": num_distinct_roles,
            "roleBreakdown": role_counts,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalUsers": total_users, "distinctRoles": distinct_roles},
        metadata={"transformationId": "isRBACEnforced", "vendor": "Anthropic", "category": "artificial-intelligence"},
    )
