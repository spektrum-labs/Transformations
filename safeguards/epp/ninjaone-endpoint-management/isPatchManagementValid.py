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


FAILURE_STATUSES = {
    "FAILED",
    "FAILED_DOWNLOAD",
    "FAILED_INSTALL",
    "REJECTED",
    "ERROR",
    "CANCELLED",
    "TIMED_OUT",
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

    total = len(records)
    status_counts = {}
    failed_count = 0
    installed_count = 0
    devices_with_failures = set()

    for rec in records:
        if not isinstance(rec, dict):
            continue
        status = rec.get("status") or "UNKNOWN"
        status_counts[status] = (status_counts.get(status) or 0) + 1
        if status in FAILURE_STATUSES:
            failed_count = failed_count + 1
            device_id = rec.get("deviceId")
            if device_id is not None:
                devices_with_failures.add(device_id)
        elif status == "INSTALLED":
            installed_count = installed_count + 1

    # failure_rate is undefined (None) when there are no records to evaluate;
    # otherwise it's the fraction of records in FAILURE_STATUSES.
    failure_rate = (failed_count / total) * 100.0 if total > 0 else None

    # is_valid is derived purely from data seen in the payload: it requires
    # at least one patch-install record AND a low observed failure rate.
    is_valid = (total > 0) and (failure_rate is not None) and (failure_rate < 5.0)

    status_summary = ", ".join([f"{k}={v}" for k, v in status_counts.items()]) if status_counts else "no records"

    result = {
        "isPatchManagementValid": is_valid,
        "totalPatchInstallRecords": total,
        "failedPatchInstallCount": failed_count,
        "installedPatchCount": installed_count,
        "failureRatePercentage": round(failure_rate, 2) if failure_rate is not None else None,
    }

    if total == 0:
        return create_response(
            result=result,
            validation=validation,
            fail_reasons=["No patch install records were returned by getOSPatchInstalls, so patch management operation cannot be confirmed from this response."],
            recommendations=["Verify the NinjaOne patch management module is enabled and reporting for at least one device."],
            input_summary={"totalRecords": 0},
            metadata={"transformationId": "isPatchManagementValid", "vendor": "NinjaOne Endpoint management", "category": "epp"},
        )

    if is_valid:
        pass_reasons = [
            f"Patch install history shows {failed_count} failed records out of {total} total ({round(failure_rate, 2)}% failure rate), status breakdown: {status_summary}.",
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"Patch install history shows {failed_count} failed records out of {total} total ({round(failure_rate, 2)}% failure rate), status breakdown: {status_summary}.",
        ]
        recommendations = [
            f"Investigate patch failures on affected devices ({len(devices_with_failures)} distinct devices with failed installs) and re-run patch scans to resolve the backlog.",
        ]

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalRecords": total, "statusCounts": status_counts},
        metadata={"transformationId": "isPatchManagementValid", "vendor": "NinjaOne Endpoint management", "category": "epp"},
    )
