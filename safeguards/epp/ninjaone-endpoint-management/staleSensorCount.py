import json
from datetime import datetime

STALE_THRESHOLD_DAYS = 14
SECONDS_PER_DAY = 86400


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
        devices = data.get("data") or data.get("apiResponse") or data.get("results") or []
        if not isinstance(devices, list):
            devices = []
    else:
        devices = []

    now_epoch = datetime.utcnow().timestamp()
    stale_threshold_epoch = now_epoch - (STALE_THRESHOLD_DAYS * SECONDS_PER_DAY)

    total_devices = len(devices)
    stale_devices = []
    missing_last_contact = 0

    for device in devices:
        if not isinstance(device, dict):
            continue
        last_contact = device.get("lastContact")
        if last_contact is None:
            missing_last_contact = missing_last_contact + 1
            continue
        try:
            last_contact_val = float(last_contact)
        except (TypeError, ValueError):
            missing_last_contact = missing_last_contact + 1
            continue
        if last_contact_val < stale_threshold_epoch:
            stale_devices.append({
                "id": device.get("id"),
                "systemName": device.get("systemName"),
                "lastContact": last_contact_val,
            })

    stale_count = len(stale_devices)

    input_summary = {
        "totalDevices": total_devices,
        "staleThresholdDays": STALE_THRESHOLD_DAYS,
        "devicesMissingLastContact": missing_last_contact,
        "staleDeviceCount": stale_count,
    }

    if total_devices == 0:
        return create_response(
            result={"staleSensorCount": stale_count, "totalDevices": total_devices},
            validation=validation,
            fail_reasons=["No device records were returned by getDevicesDetailed; unable to evaluate staleness."],
            recommendations=["Verify the NinjaOne integration is returning device inventory data."],
            input_summary=input_summary,
            metadata={"transformationId": "staleSensorCount", "vendor": "NinjaOne Endpoint Management", "category": "epp"},
        )

    sample_names = [d.get("systemName") or str(d.get("id")) for d in stale_devices[:5]]

    if stale_count > 0:
        pass_reasons = [
            f"{stale_count} of {total_devices} devices have lastContact older than {STALE_THRESHOLD_DAYS} days "
            f"(examples: {', '.join([n for n in sample_names if n])})."
        ]
    else:
        pass_reasons = [
            f"All {total_devices} devices have lastContact within the last {STALE_THRESHOLD_DAYS} days; {stale_count} stale sensors detected."
        ]

    fail_reasons = []
    recommendations = []
    if stale_count > 0:
        recommendations = [
            "Investigate and re-enroll or decommission devices that have not checked in for 14+ days: "
            + ", ".join([n for n in sample_names if n])
        ]

    return create_response(
        result={
            "staleSensorCount": stale_count,
            "totalDevices": total_devices,
            "devicesMissingLastContact": missing_last_contact,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={"transformationId": "staleSensorCount", "vendor": "NinjaOne Endpoint Management", "category": "epp"},
    )
