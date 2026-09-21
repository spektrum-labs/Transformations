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
        keys = data
    elif isinstance(data, dict):
        keys = data.get("data") or []
    else:
        keys = []

    if not isinstance(keys, list):
        keys = []

    active_keys = [k for k in keys if isinstance(k, dict) and k.get("status") == "active"]
    total_active = len(active_keys)

    org_scoped_active = []
    workspace_scoped_active = []
    unknown_scoped_active = []

    for k in active_keys:
        scope = k.get("scope") or {}
        scope_type = scope.get("type") if isinstance(scope, dict) else None
        if scope_type == "organization":
            org_scoped_active.append(k)
        elif scope_type == "workspace":
            workspace_scoped_active.append(k)
        else:
            unknown_scoped_active.append(k)

    org_count = len(org_scoped_active)
    workspace_count = len(workspace_scoped_active)
    unknown_count = len(unknown_scoped_active)

    enforced = total_active > 0 and org_count == 0

    org_names = [k.get("name") or k.get("id") or "unknown" for k in org_scoped_active]

    if total_active == 0:
        fail_reasons = ["No active API keys were found in the response, so scoped-access enforcement cannot be confirmed."]
        pass_reasons = []
        recommendations = ["Ensure the Admin API key has access to list API keys and that active keys exist."]
    elif enforced:
        pass_reasons = [
            f"All {total_active} active API keys carry scope.type='workspace' ({workspace_count} of {total_active}); no organization-wide scoped active key was found."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"{org_count} of {total_active} active API keys have scope.type='organization' (org-wide access), e.g. {', '.join(org_names[:5])}. This grants blast radius beyond a single workspace."
        ]
        recommendations = [
            "Reissue organization-scoped API keys as workspace-scoped keys (scope.type='workspace') to limit the blast radius of a leaked key."
        ]

    result = {
        "isPermissionGroupScopedAPIAccessEnforced": enforced,
        "totalActiveApiKeys": total_active,
        "organizationScopedActiveApiKeys": org_count,
        "workspaceScopedActiveApiKeys": workspace_count,
        "unknownScopedActiveApiKeys": unknown_count,
    }

    input_summary = {
        "totalKeysInResponse": len(keys),
        "totalActiveApiKeys": total_active,
        "organizationScopedActiveApiKeys": org_count,
        "workspaceScopedActiveApiKeys": workspace_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isPermissionGroupScopedAPIAccessEnforced",
            "vendor": "Anthropic",
            "category": "artificial-intelligence",
        },
    )
