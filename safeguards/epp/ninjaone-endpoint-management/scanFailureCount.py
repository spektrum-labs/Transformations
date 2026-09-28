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
        records = data
    elif isinstance(data, dict):
        records = data.get("results") or data.get("data") or []
        if not isinstance(records, list):
            records = []
    else:
        records = []

    failed_device_ids = set()
    failed_record_count = 0
    total_records = len(records)
    status_counts = {}

    for rec in records:
        if not isinstance(rec, dict):
            continue
        status = rec.get("status") or "UNKNOWN"
        status_counts[status] = status_counts.get(status, 0) + 1
        if status == "FAILED":
            failed_record_count = failed_record_count + 1
            device_id = rec.get("deviceId")
            if device_id is not None:
                failed_device_ids.add(device_id)

    scan_failure_count = len(failed_device_ids)

    transformation_errors = []
    if total_records == 0:
        transformation_errors.append("No OS patch records found in report")

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if scan_failure_count == 0:
        pass_reasons.append(
            f"No devices reported a FAILED status across {total_records} patch records in the Pending/Failed/Rejected OS Patches report (status distribution: {status_counts})."
        )
    else:
        fail_reasons.append(
            f"{scan_failure_count} distinct device(s) reported a FAILED status ({failed_record_count} failed patch records) out of {total_records} total patch records (status distribution: {status_counts})."
        )
        recommendations.append(
            "Investigate devices with FAILED patch status and re-trigger the OS patch scan/install cycle for those devices."
        )

    result = {
        "scanFailureCount": scan_failure_count,
        "totalPatchRecords": total_records,
        "failedPatchRecords": failed_record_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalPatchRecords": total_records,
            "failedPatchRecords": failed_record_count,
            "distinctFailedDevices": scan_failure_count,
            "statusCounts": status_counts,
        },
        transformation_errors=transformation_errors,
        metadata={
            "transformationId": "scanFailureCount",
            "vendor": "NinjaOne",
            "category": "epp",
        },
    )
