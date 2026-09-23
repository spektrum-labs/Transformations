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
        devices = data.get("data") or data.get("devices") or data.get("apiResponse") or []
        if not isinstance(devices, list):
            devices = []
    else:
        devices = []

    total_devices = len(devices)
    devices_with_maintenance = []
    bounded_count = 0
    unbounded_count = 0

    for d in devices:
        if not isinstance(d, dict):
            continue
        maintenance = d.get("maintenance")
        if isinstance(maintenance, dict) and maintenance:
            devices_with_maintenance.append(d)
            start = maintenance.get("start")
            end = maintenance.get("end")
            if start is not None and end is not None:
                bounded_count = bounded_count + 1
            else:
                unbounded_count = unbounded_count + 1

    maintenance_seen = len(devices_with_maintenance)

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if maintenance_seen == 0:
        is_time_limited = False
        fail_reasons.append(
            "No device records in the getDevicesDetailed response (%d devices scanned) carry a populated 'maintenance' object, so no active or configured maintenance window could be inspected for a start/end bound." % total_devices
        )
        recommendations.append(
            "Place a device into maintenance mode and re-scan, or verify via the NinjaOne console that maintenance windows are configured with both a start and end timestamp rather than left open-ended."
        )
    elif unbounded_count > 0:
        is_time_limited = False
        fail_reasons.append(
            "%d of %d devices with a maintenance object have a start timestamp but no end timestamp, indicating an indefinite (non-time-limited) maintenance suppression." % (unbounded_count, maintenance_seen)
        )
        recommendations.append(
            "Configure all maintenance mode windows with an explicit end time so alert suppression is automatically bounded."
        )
    else:
        is_time_limited = True
        pass_reasons.append(
            "All %d devices carrying a maintenance object have both 'start' and 'end' epoch fields populated, confirming maintenance windows are bounded rather than indefinite." % maintenance_seen
        )

    result = {
        "isMaintenanceModeTimeLimited": is_time_limited,
        "devicesWithMaintenanceWindow": maintenance_seen,
        "boundedMaintenanceWindows": bounded_count,
        "unboundedMaintenanceWindows": unbounded_count,
        "totalDevicesScanned": total_devices,
    }

    input_summary = {
        "totalDevicesScanned": total_devices,
        "devicesWithMaintenanceWindow": maintenance_seen,
        "boundedMaintenanceWindows": bounded_count,
        "unboundedMaintenanceWindows": unbounded_count,
    }

    return create_response(
        result=result,
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
