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


STALE_THRESHOLD_SECONDS = 14 * 24 * 60 * 60


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

    now_ts = datetime.utcnow().timestamp()

    stale_devices = []
    total_devices = 0
    missing_lastcontact = 0

    for device in devices:
        if not isinstance(device, dict):
            continue
        total_devices = total_devices + 1
        last_contact = device.get("lastContact")
        if last_contact is None:
            missing_lastcontact = missing_lastcontact + 1
            continue
        try:
            last_contact_val = float(last_contact)
        except (TypeError, ValueError):
            missing_lastcontact = missing_lastcontact + 1
            continue
        age_seconds = now_ts - last_contact_val
        if age_seconds > STALE_THRESHOLD_SECONDS:
            stale_devices.append({
                "id": device.get("id"),
                "systemName": device.get("systemName"),
                "lastContact": last_contact_val,
            })

    stale_count = len(stale_devices)

    sample_names = [d.get("systemName") for d in stale_devices[:5] if d.get("systemName")]

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if total_devices == 0:
        fail_reasons.append("No device records were returned by getDevicesDetailed; staleSensorCount could not be computed.")
        recommendations.append("Verify the getDevicesDetailed endpoint is returning the enrolled device fleet.")
    else:
        if stale_count > 0:
            names_str = ", ".join(sample_names) if sample_names else "N/A"
            fail_reasons.append(
                f"{stale_count} of {total_devices} devices have lastContact older than 14 days (threshold {STALE_THRESHOLD_SECONDS} seconds). Sample stale devices: {names_str}."
            )
            recommendations.append(
                "Investigate and remediate devices with stale lastContact timestamps (agent connectivity, decommissioned hosts, or network issues) and re-approve or remove non-reporting endpoints."
            )
        else:
            pass_reasons.append(
                f"All {total_devices} devices report lastContact within the 14-day staleness threshold ({STALE_THRESHOLD_SECONDS} seconds)."
            )

    if missing_lastcontact > 0:
        fail_reasons.append(
            f"{missing_lastcontact} of {total_devices} devices had a missing or unparsable lastContact value and were excluded from the stale calculation."
        )

    result = {
        "staleSensorCount": stale_count,
        "totalDevices": total_devices,
        "missingLastContact": missing_lastcontact,
    }

    input_summary = {
        "totalDevices": total_devices,
        "staleDevices": stale_count,
        "missingLastContact": missing_lastcontact,
        "staleThresholdSeconds": STALE_THRESHOLD_SECONDS,
    }

    metadata = {
        "transformationId": "staleSensorCount",
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
