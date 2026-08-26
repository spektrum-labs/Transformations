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
    else:
        results = []

    if not isinstance(results, list):
        results = []

    failed_records = []
    pending_count = 0
    rejected_count = 0
    failed_device_ids = {}

    for rec in results:
        if not isinstance(rec, dict):
            continue
        status = str(rec.get("status") or "").upper()
        if status == "FAILED":
            failed_records.append(rec)
            device_id = rec.get("deviceId")
            if device_id is not None:
                failed_device_ids[device_id] = True
        elif status == "PENDING":
            pending_count = pending_count + 1
        elif status == "REJECTED":
            rejected_count = rejected_count + 1

    scan_failure_count = len(failed_device_ids) if failed_device_ids else len(failed_records)

    sample_names = []
    for rec in failed_records[:5]:
        nm = rec.get("name") or rec.get("kbNumber") or "unknown patch"
        did = rec.get("deviceId")
        sample_names.append(f"{nm} on device {did}")

    if scan_failure_count > 0:
        pass_reasons = []
        fail_reasons = [
            f"{scan_failure_count} device(s) report a FAILED OS patch status in the pending/failed/rejected patches report. "
            f"Examples: {'; '.join(sample_names)}."
        ]
        recommendations = [
            "Investigate and remediate the failed OS patch installations on the affected devices, then re-run the patch scan cycle."
        ]
    else:
        pass_reasons = [
            f"No devices report a FAILED OS patch status among {len(results)} records inspected in the pending/failed/rejected patches report "
            f"(pending={pending_count}, rejected={rejected_count})."
        ]
        fail_reasons = []
        recommendations = []

    result = {
        "scanFailureCount": scan_failure_count,
        "totalRecordsInspected": len(results),
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
            "totalRecords": len(results),
            "failedCount": scan_failure_count,
            "pendingCount": pending_count,
            "rejectedCount": rejected_count,
        },
        metadata={
            "transformationId": "scanFailureCount",
            "vendor": "NinjaOne Endpoint Management",
            "category": "epp",
        },
    )
