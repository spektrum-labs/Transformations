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
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
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
    data = data if isinstance(data, dict) else {}

    # getDevicesDetailed returns a columnar shape: parallel arrays keyed by field name,
    # OR (in some captures) a list of per-device dict rows under "data"/"items".
    # Normalize both into a list of per-device os records.
    devices = []

    raw_items = data.get("data") if isinstance(data.get("data"), list) else None
    if raw_items is None:
        raw_items = data.get("items") if isinstance(data.get("items"), list) else None

    if raw_items is not None:
        for row in raw_items:
            if isinstance(row, dict):
                devices.append(row)
    else:
        # columnar shape: id, organizationId, offline, approvalStatus, maintenance, os are parallel lists
        ids = data.get("id") if isinstance(data.get("id"), list) else []
        os_list = data.get("os") if isinstance(data.get("os"), list) else []
        count = len(ids) if ids else len(os_list)
        for i in range(count):
            os_val = os_list[i] if i < len(os_list) else None
            devices.append({"os": os_val})

    total_devices = len(devices)

    devices_with_os_version = 0
    sample_visible = None
    sample_missing = None

    for dev in devices:
        os_obj = dev.get("os") if isinstance(dev, dict) else None
        os_obj = os_obj if isinstance(os_obj, dict) else {}
        has_name = bool(os_obj.get("name"))
        has_build = bool(os_obj.get("buildNumber")) or bool(os_obj.get("version")) or bool(os_obj.get("releaseId"))
        if has_name and has_build:
            devices_with_os_version = devices_with_os_version + 1
            if sample_visible is None:
                sample_visible = os_obj
        else:
            if sample_missing is None:
                sample_missing = os_obj

    if total_devices == 0:
        is_visible = False
        pass_reasons = []
        fail_reasons = [
            "No device records were returned by getDevicesDetailed, so OS name/build/version "
            "could not be confirmed as retrievable for any managed device."
        ]
        recommendations = [
            "Verify devices-detailed API access and that managed devices exist in the tenant, "
            "then re-run this check."
        ]
        input_summary = {"totalDevices": 0, "devicesWithOsVersion": 0}
    else:
        coverage = devices_with_os_version / total_devices
        is_visible = devices_with_os_version == total_devices
        input_summary = {
            "totalDevices": total_devices,
            "devicesWithOsVersion": devices_with_os_version,
        }
        if is_visible:
            pass_reasons = [
                f"All {total_devices} device records returned by getDevicesDetailed carry a "
                f"populated os.name plus os.buildNumber/version/releaseId field "
                f"(sample: {sample_visible})."
            ]
            fail_reasons = []
            recommendations = []
        else:
            pass_reasons = []
            fail_reasons = [
                f"Only {devices_with_os_version} of {total_devices} devices "
                f"(coverage {round(coverage * 100, 1)}%) have both os.name and an "
                f"os build/version field populated in getDevicesDetailed "
                f"(example missing record: {sample_missing})."
            ]
            recommendations = [
                "Ensure the NinjaOne agent is reporting full OS inventory (name and build/version) "
                "for every managed device; devices missing this data may be offline, unenrolled, "
                "or running an outdated agent."
            ]

    return create_response(
        result={"isDeviceOSVersionVisible": is_visible, "totalDevices": total_devices, "devicesWithOsVersion": devices_with_os_version},
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={"transformationId": "isDeviceOSVersionVisible", "vendor": "NinjaOne Endpoint Management", "category": "epp"},
    )
