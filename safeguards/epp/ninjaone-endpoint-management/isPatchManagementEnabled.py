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

    total_records = len(records)

    distinct_devices = set()
    status_counts = {}
    for rec in records:
        if not isinstance(rec, dict):
            continue
        device_id = rec.get("deviceId")
        if device_id is not None:
            distinct_devices.add(device_id)
        status = rec.get("status") or "UNKNOWN"
        status_counts[status] = status_counts.get(status, 0) + 1

    installed_count = status_counts.get("INSTALLED", 0)
    distinct_device_count = len(distinct_devices)

    is_enabled = total_records > 0 and distinct_device_count > 0

    input_summary = {
        "totalPatchInstallRecords": total_records,
        "distinctDevicesWithPatchHistory": distinct_device_count,
        "statusBreakdown": status_counts,
    }

    if is_enabled:
        pass_reasons = [
            f"OS patch install history returned {total_records} patch records "
            f"across {distinct_device_count} distinct devices (deviceId), with "
            f"{installed_count} records showing status=INSTALLED. This confirms "
            f"OS patch scanning/deployment is active via NinjaOne policy."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"The os-patch-installs report returned {total_records} records across "
            f"{distinct_device_count} devices, showing no evidence of active patch "
            f"deployment history for the managed fleet."
        ]
        recommendations = [
            "Verify that a NinjaOne policy with OS Patch Management enabled is "
            "assigned to managed devices, and that patch scans have run recently."
        ]

    result = {
        "isPatchManagementEnabled": is_enabled,
        "totalPatchInstallRecords": total_records,
        "distinctDevicesWithPatchHistory": distinct_device_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isPatchManagementEnabled",
            "vendor": "NinjaOne",
            "category": "epp",
        },
    )
