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
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
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
    data = data if isinstance(data, dict) else {}

    results = data.get("results") or []
    if not isinstance(results, list):
        results = []

    failed_device_ids = []
    failed_row_count = 0
    total_rows = 0
    status_counts = {}

    for row in results:
        if not isinstance(row, dict):
            continue
        total_rows = total_rows + 1
        status = row.get("status")
        status_key = status if isinstance(status, str) else "UNKNOWN"
        status_upper = status_key.upper()
        status_counts[status_upper] = (status_counts.get(status_upper) or 0) + 1
        if status_upper == "FAILED":
            failed_row_count = failed_row_count + 1
            device_id = row.get("deviceId")
            if device_id is not None and device_id not in failed_device_ids:
                failed_device_ids.append(device_id)

    scan_failure_count = len(failed_device_ids)

    input_summary = {
        "totalRows": total_rows,
        "failedRows": failed_row_count,
        "distinctFailedDevices": scan_failure_count,
        "statusCounts": status_counts,
    }

    if total_rows == 0:
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = ["No OS patch install/pending records returned for the current scan cycle - "
                                "scanFailureCount defaulted to 0."]
    elif scan_failure_count == 0:
        pass_reasons = [
            f"No devices reported a FAILED status across {total_rows} OS patch install records "
            f"in the current scan cycle (statusCounts={status_counts})."
        ]
        fail_reasons = []
        recommendations = []
        additional_findings = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"{scan_failure_count} distinct device(s) (deviceIds={failed_device_ids}) report a FAILED "
            f"status out of {total_rows} OS patch install/pending records this scan cycle "
            f"(statusCounts={status_counts})."
        ]
        recommendations = [
            "Investigate the failed OS patch installs on the affected devices and re-trigger the "
            "patch scan/install to remediate the failures."
        ]
        additional_findings = []

    result = {
        "scanFailureCount": scan_failure_count,
        "totalPatchInstallRecords": total_rows,
        "failedRecordCount": failed_row_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "scanFailureCount",
            "vendor": "NinjaOne Endpoint Management",
            "category": "epp",
        },
        additional_findings=additional_findings,
    )
