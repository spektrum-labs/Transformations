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

    settings_list = []
    if isinstance(data, dict):
        settings_list = data.get("settings") or []
    if not isinstance(settings_list, list):
        settings_list = []

    settings_by_name = {}
    for row in settings_list:
        if isinstance(row, dict) and row.get("name"):
            settings_by_name[row["name"]] = row.get("value")

    provisioning_mode = settings_by_name.get("sso_provisioning_mode")
    directory_sync_enabled = settings_by_name.get("directory_sync_enabled")

    is_scim = False
    if isinstance(provisioning_mode, str) and provisioning_mode.strip().lower() == "scim":
        is_scim = True
    if directory_sync_enabled is True:
        is_scim = True

    transformation_errors = []
    if not settings_list:
        transformation_errors.append("No settings array found in effective_organization_settings response")

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_scim:
        pass_reasons.append(
            f"Organization settings report sso_provisioning_mode='{provisioning_mode}' and "
            f"directory_sync_enabled={directory_sync_enabled}, indicating SCIM directory sync provisions users."
        )
    else:
        fail_reasons.append(
            f"Organization settings report sso_provisioning_mode='{provisioning_mode}' and "
            f"directory_sync_enabled={directory_sync_enabled}, neither of which indicates active SCIM provisioning."
        )
        recommendations.append(
            "Enable SCIM directory sync (set sso_provisioning_mode to 'scim' and enable directory_sync_enabled) "
            "in the organization's SSO/provisioning settings so user accounts are provisioned/deprovisioned "
            "automatically rather than via manual invites."
        )

    result = {
        "isSCIMProvisioningEnabled": is_scim,
        "ssoProvisioningMode": provisioning_mode,
        "directorySyncEnabled": directory_sync_enabled,
    }

    input_summary = {
        "totalSettings": len(settings_list),
        "ssoProvisioningMode": provisioning_mode,
        "directorySyncEnabled": directory_sync_enabled,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isSCIMProvisioningEnabled",
            "vendor": "Anthropic Claude Developer Platform Claude API",
            "category": "artificial-intelligence",
        },
        transformation_errors=transformation_errors,
    )
