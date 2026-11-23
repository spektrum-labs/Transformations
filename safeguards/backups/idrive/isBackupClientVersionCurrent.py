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


def version_tuple(v):
    parts = []
    current = ""
    for ch in v:
        if ch.isdigit():
            current = current + ch
        else:
            if current != "":
                parts.append(int(current))
                current = ""
    if current != "":
        parts.append(int(current))
    return tuple(parts)


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    if isinstance(data, list):
        devices = data
    elif isinstance(data, dict):
        devices = data.get("data") or data.get("apiResponse") or []
        if not isinstance(devices, list):
            devices = []
    else:
        devices = []

    total_devices = len(devices)

    versions = []
    devices_with_version = []
    for d in devices:
        if not isinstance(d, dict):
            continue
        v = d.get("version")
        if v:
            versions.append(v)
            devices_with_version.append({"device_id": d.get("device_id"), "name": d.get("name"), "version": v})

    devices_reporting = len(devices_with_version)

    unique_versions = sorted(set(versions), key=version_tuple) if versions else []
    latest_version = unique_versions[-1] if unique_versions else None

    on_latest = [dv for dv in devices_with_version if dv["version"] == latest_version] if latest_version else []
    off_latest = [dv for dv in devices_with_version if dv["version"] != latest_version] if latest_version else []

    all_current = (devices_reporting > 0) and (len(off_latest) == 0)

    result = {
        "isBackupClientVersionCurrent": all_current,
        "totalDevices": total_devices,
        "devicesReportingVersion": devices_reporting,
        "devicesOnLatestVersion": len(on_latest),
        "latestObservedVersion": latest_version,
    }

    if devices_reporting == 0:
        return create_response(
            result=result,
            validation=validation,
            fail_reasons=[
                "No devices with a reported backup client version were found in getDeviceSummary "
                f"(total_devices={total_devices}); cannot confirm backup client version currency."
            ],
            recommendations=[
                "Ensure at least one device is enrolled and reporting a backup client version via getDeviceSummary.",
            ],
            input_summary={"totalDevices": total_devices, "devicesReportingVersion": devices_reporting},
            metadata={
                "transformationId": "isBackupClientVersionCurrent",
                "vendor": "IDrive",
                "category": "backup",
            },
        )

    if all_current:
        pass_reasons = [
            f"All {devices_reporting} devices reporting a backup client version are on the "
            f"fleet's latest observed version '{latest_version}' (field: version, from getDeviceSummary)."
        ]
        fail_reasons = []
        recommendations = []
    else:
        sample_off = off_latest[:5]
        sample_desc = ", ".join(
            f"{dv.get('name') or dv.get('device_id')}={dv.get('version')}" for dv in sample_off
        )
        pass_reasons = []
        fail_reasons = [
            f"{len(off_latest)} of {devices_reporting} devices reporting a version are not on the "
            f"fleet's latest observed version '{latest_version}' (field: version, from getDeviceSummary). "
            f"Examples: {sample_desc}."
        ]
        recommendations = [
            "Upgrade the backup client on out-of-date devices to the latest observed version "
            f"'{latest_version}' to bring the fleet's backup agents current.",
        ]

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalDevices": total_devices,
            "devicesReportingVersion": devices_reporting,
            "devicesOnLatestVersion": len(on_latest),
            "latestObservedVersion": latest_version,
        },
        metadata={
            "transformationId": "isBackupClientVersionCurrent",
            "vendor": "IDrive",
            "category": "backup",
        },
    )
