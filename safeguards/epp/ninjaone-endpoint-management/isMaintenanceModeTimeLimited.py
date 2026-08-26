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
        devices = data
    elif isinstance(data, dict):
        devices = data.get("data") or data.get("results") or []
        if not isinstance(devices, list):
            devices = []
    else:
        devices = []

    total_devices = len(devices)

    maintenance_windows = []
    for device in devices:
        if not isinstance(device, dict):
            continue
        maint = device.get("maintenance")
        if isinstance(maint, list):
            for entry in maint:
                if isinstance(entry, dict) and entry:
                    maintenance_windows.append(entry)
        elif isinstance(maint, dict) and maint:
            maintenance_windows.append(maint)

    bounded_count = 0
    unbounded_count = 0
    unbounded_samples = []
    for entry in maintenance_windows:
        start_val = entry.get("start")
        end_val = entry.get("end")
        if start_val and end_val:
            bounded_count = bounded_count + 1
        else:
            unbounded_count = unbounded_count + 1
            if len(unbounded_samples) < 3:
                unbounded_samples.append(entry)

    total_windows = len(maintenance_windows)

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if total_windows == 0:
        is_time_limited = True
        pass_reasons.append(
            f"Scanned {total_devices} devices via getDevicesDetailed and found no active maintenance windows "
            f"(all 'maintenance' fields were empty), so no indefinite-suppression window is currently present."
        )
    else:
        if unbounded_count == 0:
            is_time_limited = True
            pass_reasons.append(
                f"All {total_windows} maintenance window(s) observed across {total_devices} devices include both "
                f"'start' and 'end' timestamps, confirming maintenance mode is time-bounded rather than indefinite."
            )
        else:
            is_time_limited = False
            fail_reasons.append(
                f"{unbounded_count} of {total_windows} maintenance window(s) across {total_devices} devices are "
                f"missing a 'start' or 'end' timestamp, indicating an indefinite (unbounded) maintenance suppression."
            )
            recommendations.append(
                "Configure an explicit end time for all maintenance windows so alert suppression cannot persist indefinitely."
            )

    result = {
        "isMaintenanceModeTimeLimited": is_time_limited,
        "totalDevices": total_devices,
        "totalMaintenanceWindows": total_windows,
        "boundedWindows": bounded_count,
        "unboundedWindows": unbounded_count,
    }

    input_summary = {
        "totalDevices": total_devices,
        "totalMaintenanceWindows": total_windows,
        "boundedWindows": bounded_count,
        "unboundedWindows": unbounded_count,
    }

    metadata = {
        "transformationId": "isMaintenanceModeTimeLimited",
        "vendor": "NinjaOne Endpoint Management",
        "category": "epp",
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
