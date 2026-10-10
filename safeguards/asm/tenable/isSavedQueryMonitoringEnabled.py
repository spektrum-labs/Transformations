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
        folders = data
    elif isinstance(data, dict):
        folders = data.get("apiResponse") or data.get("data") or []
        if not isinstance(folders, list):
            folders = []
    else:
        folders = []

    total_folders = len(folders)
    monitored_folders = []
    for f in folders:
        if not isinstance(f, dict):
            continue
        filters = f.get("filters") or []
        updated_at = f.get("updated_at")
        if isinstance(filters, list) and len(filters) > 0 and updated_at:
            monitored_folders.append(f)

    monitored_count = len(monitored_folders)
    is_enabled = monitored_count > 0

    sample_names = [f.get("name") for f in monitored_folders[:5] if isinstance(f, dict)]

    if is_enabled:
        pass_reasons = [
            f"{monitored_count} of {total_folders} Smart Folders (saved queries) have active filters and an updated_at timestamp, e.g. {sample_names}, indicating auto-refreshing saved-query monitoring is configured.",
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"No Smart Folders (saved queries) were found with both non-empty filters and an updated_at timestamp out of {total_folders} total folders.",
        ]
        recommendations = [
            "Create at least one Smart Folder (saved query) with active filters in Tenable ASM so a filtered risk view auto-refreshes without manual re-running.",
        ]

    result = {
        "isSavedQueryMonitoringEnabled": is_enabled,
        "totalSmartFolders": total_folders,
        "monitoredSmartFolders": monitored_count,
    }

    input_summary = {
        "totalSmartFolders": total_folders,
        "monitoredSmartFolders": monitored_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isSavedQueryMonitoringEnabled",
            "vendor": "Tenable",
            "category": "asm",
        },
    )
