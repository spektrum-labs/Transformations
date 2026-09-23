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
        devices = data.get("data") or data.get("devices") or []
        if not isinstance(devices, list):
            devices = []
    else:
        devices = []

    total_devices = len(devices)
    devices_in_maintenance = 0
    unbounded_devices = []
    bounded_devices = []

    for d in devices:
        if not isinstance(d, dict):
            continue
        m = d.get("maintenance")
        if not isinstance(m, dict):
            continue
        devices_in_maintenance = devices_in_maintenance + 1
        end_val = m.get("end")
        if end_val is None:
            end_val = m.get("endTime")
        device_label = d.get("displayName") or d.get("systemName") or d.get("id")
        if end_val is None:
            unbounded_devices.append(device_label)
        else:
            bounded_devices.append(device_label)

    if devices_in_maintenance == 0:
        is_time_limited = True
        pass_reasons = [
            f"No devices currently report an active maintenance object out of {total_devices} devices scanned via listDevices; there are no indefinite maintenance windows to flag."
        ]
        fail_reasons = []
        recommendations = []
    elif len(unbounded_devices) == 0:
        is_time_limited = True
        pass_reasons = [
            f"All {devices_in_maintenance} device(s) currently in maintenance mode have a defined 'end' timestamp (devices: {bounded_devices})."
        ]
        fail_reasons = []
        recommendations = []
    else:
        is_time_limited = False
        pass_reasons = []
        fail_reasons = [
            f"{len(unbounded_devices)} of {devices_in_maintenance} device(s) in maintenance mode have no 'end' timestamp set (devices: {unbounded_devices}), meaning maintenance mode is indefinite."
        ]
        recommendations = [
            "Set an explicit end time for maintenance windows on all devices instead of leaving maintenance mode open-ended."
        ]

    input_summary = {
        "totalDevices": total_devices,
        "devicesInMaintenance": devices_in_maintenance,
        "unboundedMaintenanceDevices": len(unbounded_devices),
        "boundedMaintenanceDevices": len(bounded_devices),
    }

    return create_response(
        result={
            "isMaintenanceModeTimeLimited": is_time_limited,
            "totalDevices": total_devices,
            "devicesInMaintenance": devices_in_maintenance,
            "unboundedMaintenanceDevices": len(unbounded_devices),
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isMaintenanceModeTimeLimited",
            "vendor": "NinjaOne",
            "category": "epp",
        },
    )
