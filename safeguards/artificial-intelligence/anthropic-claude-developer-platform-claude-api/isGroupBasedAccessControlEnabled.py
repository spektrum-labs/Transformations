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
        groups = data
    elif isinstance(data, dict):
        groups = data.get("data") or []
        if not isinstance(groups, list):
            groups = []
    else:
        groups = []

    total_groups = len(groups)
    groups_with_roles = 0
    scim_groups = 0
    group_names = []

    for g in groups:
        if not isinstance(g, dict):
            continue
        roles = g.get("roles") or []
        name = g.get("name") or g.get("id") or "unnamed"
        if isinstance(roles, list) and len(roles) > 0:
            groups_with_roles = groups_with_roles + 1
            group_names.append(name)
        if g.get("source_type") == "scim":
            scim_groups = scim_groups + 1

    is_enabled = groups_with_roles > 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_enabled:
        sample = ", ".join(group_names[:5])
        pass_reasons.append(
            f"Found {groups_with_roles} of {total_groups} compliance group(s) with non-empty role mappings "
            f"(e.g. {sample}), indicating access is managed via enterprise groups rather than per-user role assignment."
        )
        if scim_groups > 0:
            pass_reasons.append(
                f"{scim_groups} of {total_groups} groups have source_type='scim', confirming directory-driven group sync."
            )
    else:
        fail_reasons.append(
            f"listComplianceGroups returned {total_groups} group(s), none of which carry a non-empty roles array. "
            "No evidence that access is managed via enterprise groups with role attachments."
        )
        recommendations.append(
            "Create enterprise groups (via SCIM/directory sync or the Compliance Groups API) and attach organization "
            "roles to those groups instead of assigning roles directly to individual users."
        )

    result = {
        "isGroupBasedAccessControlEnabled": is_enabled,
        "totalGroups": total_groups,
        "groupsWithRoles": groups_with_roles,
        "scimSourcedGroups": scim_groups,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalGroups": total_groups, "groupsWithRoles": groups_with_roles},
        metadata={
            "transformationId": "isGroupBasedAccessControlEnabled",
            "vendor": "Anthropic Claude Developer Platform Claude API",
            "category": "artificial-intelligence",
        },
    )
