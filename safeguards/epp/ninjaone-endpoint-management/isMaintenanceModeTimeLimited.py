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
    data = data if isinstance(data, (dict, list)) else []

    if isinstance(data, list):
        devices = data
    elif isinstance(data, dict):
        devices = data.get("data") or data.get("results") or []
        if not isinstance(devices, list):
            devices = []
    else:
        devices = []

    total_devices = len(devices)
    devices_in_maintenance = 0
    bounded_windows = 0
    unbounded_windows = 0
    unbounded_device_names = []
    bounded_device_names = []

    for device in devices:
        if not isinstance(device, dict):
            continue
        maint = device.get("maintenance")
        entries = []
        if isinstance(maint, list):
            entries = [m for m in maint if isinstance(m, dict)]
        elif isinstance(maint, dict) and maint:
            entries = [maint]

        if not entries:
            continue

        devices_in_maintenance = devices_in_maintenance + 1
        name = device.get("systemName") or ("device-%s" % str(device.get("id")))

        device_has_unbounded = False
        for entry in entries:
            end_val = entry.get("end")
            start_val = entry.get("start")
            if end_val is None or start_val is None:
                device_has_unbounded = True
                unbounded_windows = unbounded_windows + 1
            else:
                bounded_windows = bounded_windows + 1

        if device_has_unbounded:
            if len(unbounded_device_names) < 10:
                unbounded_device_names.append(name)
        else:
            if len(bounded_device_names) < 10:
                bounded_device_names.append(name)

    if devices_in_maintenance == 0:
        is_time_limited = True
        pass_reasons = [
            "Scanned %d devices via getDevicesDetailed; none currently report an active maintenance window (maintenance field empty on all records), so no indefinite suppression was observed." % total_devices
        ]
        fail_reasons = []
        recommendations = []
    elif unbounded_windows == 0:
        is_time_limited = True
        pass_reasons = [
            "Of %d devices in maintenance mode, all %d maintenance window(s) carry both start and end timestamps (bounded: %s), indicating no indefinite suppression." % (devices_in_maintenance, bounded_windows, ", ".join(bounded_device_names))
        ]
        fail_reasons = []
        recommendations = []
    else:
        is_time_limited = False
        pass_reasons = []
        fail_reasons = [
            "%d of %d devices in maintenance mode have at least one maintenance window missing a start or end timestamp (examples: %s), meaning alerts are suppressed indefinitely rather than for a bounded window." % (len(unbounded_device_names), devices_in_maintenance, ", ".join(unbounded_device_names))
        ]
        recommendations = [
            "Configure maintenance mode with an explicit end time (bounded window) on affected devices instead of leaving it open-ended."
        ]

    result = {
        "isMaintenanceModeTimeLimited": is_time_limited,
        "totalDevices": total_devices,
        "devicesInMaintenance": devices_in_maintenance,
        "boundedWindows": bounded_windows,
        "unboundedWindows": unbounded_windows,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalDevices": total_devices,
            "devicesInMaintenance": devices_in_maintenance,
            "boundedWindows": bounded_windows,
            "unboundedWindows": unbounded_windows,
        },
        metadata={
            "transformationId": "isMaintenanceModeTimeLimited",
            "vendor": "NinjaOne Endpoint Management",
            "category": "epp",
        },
    )
