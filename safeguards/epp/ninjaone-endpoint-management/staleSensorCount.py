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
        devices = data.get("data") or data.get("devices") or data.get("results") or []
        if not isinstance(devices, list):
            devices = []
    else:
        devices = []

    STALE_THRESHOLD_SECONDS = 14 * 24 * 60 * 60

    now_dt = datetime.utcnow()
    epoch_dt = datetime(1970, 1, 1)
    now_epoch = (now_dt - epoch_dt).total_seconds()

    stale_devices = []
    total_devices = 0
    devices_with_timestamp = 0

    for d in devices:
        if not isinstance(d, dict):
            continue
        total_devices = total_devices + 1
        last_contact = d.get("lastContact")
        if last_contact is None:
            continue
        try:
            last_contact_val = float(last_contact)
        except (TypeError, ValueError):
            continue
        devices_with_timestamp = devices_with_timestamp + 1
        age_seconds = now_epoch - last_contact_val
        if age_seconds >= STALE_THRESHOLD_SECONDS:
            stale_devices.append({
                "id": d.get("id"),
                "systemName": d.get("systemName"),
                "ageDays": round(age_seconds / 86400.0, 1),
            })

    stale_count = len(stale_devices)

    if devices_with_timestamp == 0:
        fail_reasons = [
            "No devices in the getDevices response carried a usable lastContact timestamp; stale sensor count cannot be computed."
        ]
        pass_reasons = []
        recommendations = [
            "Verify the getDevices endpoint is returning lastContact for managed devices."
        ]
    elif stale_count > 0:
        sample_names = [s.get("systemName") for s in stale_devices[:5] if s.get("systemName")]
        pass_reasons = []
        fail_reasons = [
            f"{stale_count} of {devices_with_timestamp} devices with a lastContact timestamp have not checked in for 14+ days (e.g. {', '.join(sample_names)})."
        ]
        recommendations = [
            "Investigate and remediate stale endpoints (e.g. Marks-MacBook-Air.local) that have not checked in for over 14 days - they may be decommissioned, powered off, or have a disconnected agent."
        ]
    else:
        pass_reasons = [
            f"All {devices_with_timestamp} devices with a lastContact timestamp checked in within the last 14 days."
        ]
        fail_reasons = []
        recommendations = []

    result = {
        "staleSensorCount": stale_count,
        "totalDevices": total_devices,
        "devicesWithTimestamp": devices_with_timestamp,
    }

    input_summary = {
        "totalDevices": total_devices,
        "devicesWithTimestamp": devices_with_timestamp,
        "staleSensorCount": stale_count,
        "staleThresholdDays": 14,
    }

    metadata = {
        "transformationId": "staleSensorCount",
        "vendor": "NinjaOne",
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
