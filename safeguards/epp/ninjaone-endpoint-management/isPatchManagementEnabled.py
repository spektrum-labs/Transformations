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
        results = data
    elif isinstance(data, dict):
        results = data.get("results") or data.get("data") or []
        if not isinstance(results, list):
            results = []
    else:
        results = []

    total_records = len(results)

    status_counts = {}
    for rec in results:
        if not isinstance(rec, dict):
            continue
        status = rec.get("status") or "UNKNOWN"
        status_counts[status] = status_counts.get(status, 0) + 1

    installed_count = status_counts.get("INSTALLED", 0) + status_counts.get("SUCCEEDED", 0) + status_counts.get("SUCCESS", 0)

    is_enabled = total_records > 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_enabled:
        status_summary = ", ".join([f"{k}={v}" for k, v in status_counts.items()])
        pass_reasons.append(
            f"OS patch install activity report returned {total_records} patch install record(s) "
            f"(status breakdown: {status_summary}), confirming OS patch management is actively running against the fleet."
        )
    else:
        fail_reasons.append(
            "The os-patch-installs report returned zero records, indicating no OS patch install "
            "activity has been observed for this tenant's devices, so OS patch management cannot be confirmed as enabled."
        )
        recommendations.append(
            "Verify that an OS patch management policy is assigned to device policies and that patch "
            "scanning/approval schedules are configured in NinjaOne so patch install activity is generated and reported."
        )

    result = {
        "isPatchManagementEnabled": is_enabled,
        "totalPatchInstallRecords": total_records,
        "installedPatchCount": installed_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalPatchInstallRecords": total_records, "statusCounts": status_counts},
        metadata={
            "transformationId": "isPatchManagementEnabled",
            "vendor": "NinjaOne Endpoint Management",
            "category": "epp",
        },
    )
