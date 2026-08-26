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
        items = data
    elif isinstance(data, dict):
        items = data.get("results") or data.get("data") or []
    else:
        items = []

    if not isinstance(items, list):
        items = []

    failed_device_ids = set()
    pending_count = 0
    rejected_count = 0
    total_records = len(items)

    for item in items:
        if not isinstance(item, dict):
            continue
        status = item.get("status") or ""
        status_upper = str(status).upper()
        device_id = item.get("deviceId")
        if status_upper == "FAILED":
            if device_id is not None:
                failed_device_ids.add(device_id)
            else:
                failed_device_ids.add(len(failed_device_ids))
        elif status_upper == "PENDING":
            pending_count = pending_count + 1
        elif status_upper == "REJECTED":
            rejected_count = rejected_count + 1

    scan_failure_count = len(failed_device_ids)

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if total_records == 0:
        fail_reasons.append(
            "No OS patch install records were returned by the os-patch-installs report; "
            "scanFailureCount could not be derived from this scan cycle's data."
        )
        recommendations.append(
            "Verify the OS patch scan cycle has executed recently and that devices are reporting patch install status."
        )
    else:
        if scan_failure_count > 0:
            pass_reasons.append(
                f"Identified {scan_failure_count} distinct device(s) with status=FAILED across "
                f"{total_records} OS patch install records ({pending_count} PENDING, {rejected_count} REJECTED)."
            )
        else:
            pass_reasons.append(
                f"No devices reported status=FAILED across {total_records} OS patch install records "
                f"({pending_count} PENDING, {rejected_count} REJECTED) in the current scan cycle."
            )

    result = {
        "scanFailureCount": scan_failure_count,
        "totalPatchInstallRecords": total_records,
        "pendingCount": pending_count,
        "rejectedCount": rejected_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalPatchInstallRecords": total_records,
            "failedDeviceCount": scan_failure_count,
            "pendingCount": pending_count,
            "rejectedCount": rejected_count,
        },
        metadata={
            "transformationId": "scanFailureCount",
            "vendor": "NinjaOne",
            "category": "epp",
        },
    )
