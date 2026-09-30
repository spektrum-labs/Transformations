
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


def parse_date(s):
    if not s or not isinstance(s, str):
        return None
    try:
        s2 = s.replace("T", " ").strip()
        parts = s2.split(" ")
        date_part = parts[0]
        time_part = parts[1] if len(parts) > 1 else "00:00:00"
        date_bits = date_part.split("-")
        if len(date_bits) != 3:
            return None
        y = int(date_bits[0])
        m = int(date_bits[1])
        d = int(date_bits[2])
        time_bits = time_part.split(":")
        hh = int(time_bits[0]) if len(time_bits) > 0 else 0
        mm = int(time_bits[1]) if len(time_bits) > 1 else 0
        ss = int(time_bits[2]) if len(time_bits) > 2 else 0
        return datetime(y, m, d, hh, mm, ss)
    except Exception:
        return None


def transform(input):
    data, validation = extract_input(input)

    if isinstance(data, list):
        devices = data
    elif isinstance(data, dict):
        devices = data.get("data") or data.get("devices") or []
        if not isinstance(devices, list):
            devices = []
    else:
        devices = []

    now = datetime.utcnow()
    bad_statuses = ["Failed", "Offline", "Blocked", "Cancelled", "Suspended"]

    stale_devices = []
    total_devices = len(devices)

    for dev in devices:
        if not isinstance(dev, dict):
            continue
        status = dev.get("backup_status") or ""
        next_backup_raw = dev.get("next_backup")
        last_backup_raw = dev.get("last_backup")
        next_backup_dt = parse_date(next_backup_raw)
        is_stale = False
        reason = ""
        if status in bad_statuses:
            is_stale = True
            reason = f"backup_status={status}"
        elif next_backup_dt is not None and next_backup_dt < now:
            is_stale = True
            reason = f"next_backup={next_backup_raw} is in the past (now={now.isoformat()})"
        elif not last_backup_raw and not next_backup_raw:
            is_stale = True
            reason = "no last_backup or next_backup timestamp recorded"

        if is_stale:
            stale_devices.append({
                "device_id": dev.get("device_id"),
                "name": dev.get("name"),
                "backup_status": status,
                "last_backup": last_backup_raw,
                "next_backup": next_backup_raw,
                "reason": reason,
            })

    stale_count = len(stale_devices)

    if total_devices == 0:
        pass_reasons = ["No devices were returned by getDeviceSummary; 0 stale protection jobs counted out of 0 total monitored devices."]
        fail_reasons = []
        recommendations = []
    elif stale_count == 0:
        pass_reasons = [
            f"All {total_devices} devices report a healthy backup_status and an up-to-date next_backup schedule; 0 stale protection jobs detected."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        sample_names = [d.get("name") or str(d.get("device_id")) for d in stale_devices[:5]]
        fail_reasons = [
            f"{stale_count} of {total_devices} devices have a stale protection job (status in {bad_statuses}, an overdue next_backup, or missing schedule timestamps). Examples: {sample_names}."
        ]
        recommendations = [
            "Investigate devices with Failed/Offline/Blocked backup_status and re-run or reschedule their backup jobs.",
            "Verify agent connectivity for devices whose next_backup date has already passed without a completed run.",
        ]

    result = {
        "staleProtectionJobsCount": stale_count,
        "totalDevices": total_devices,
    }

    input_summary = {
        "totalDevices": total_devices,
        "staleDevices": stale_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "staleProtectionJobsCount",
            "vendor": "IDrive",
            "category": "backup",
        },
    )
