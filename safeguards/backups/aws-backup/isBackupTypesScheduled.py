import json
from datetime import datetime


def extract_input(input_data):
    """Extract data and validation from input, handling enriched + legacy formats."""
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
    """Create the standardized 5-section transformation response."""
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
        data = {}

    management_pref = data.get("ResourceTypeManagementPreference") or {}
    optin_pref = data.get("ResourceTypeOptInPreference") or {}

    if not isinstance(management_pref, dict):
        management_pref = {}
    if not isinstance(optin_pref, dict):
        optin_pref = {}

    managed_types = [k for k, v in management_pref.items() if v is True]
    optin_types = [k for k, v in optin_pref.items() if v is True]

    has_managed_type = len(managed_types) > 0
    has_optin_type = len(optin_types) > 0

    is_scheduled = has_managed_type

    if is_scheduled:
        pass_reasons = [
            f"ResourceTypeManagementPreference shows {len(managed_types)} resource "
            f"type(s) actively managed by AWS Backup ({', '.join(managed_types)}), "
            "which implies an assigned backup plan with a ScheduleExpression driving "
            "automated backups for those types."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            "ResourceTypeManagementPreference contains no resource type set to true "
            f"(opted-in types checked: {', '.join(optin_types) if optin_types else 'none'}), "
            "so no evidence of an active, scheduled backup plan was found via this endpoint."
        ]
        recommendations = [
            "Create or verify a BackupPlan with a rule containing a non-empty "
            "ScheduleExpression, and ensure the relevant resource types are opted "
            "in and under active Backup management."
        ]

    result = {
        "isBackupTypesScheduled": is_scheduled,
        "managedResourceTypeCount": len(managed_types),
        "optedInResourceTypeCount": len(optin_types),
    }

    input_summary = {
        "managementPreferenceKeys": list(management_pref.keys()),
        "optInPreferenceKeys": list(optin_pref.keys()),
    }

    metadata = {
        "transformationId": "isBackupTypesScheduled",
        "vendor": "AWS Backup",
        "category": "backup",
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata=metadata,
    )
