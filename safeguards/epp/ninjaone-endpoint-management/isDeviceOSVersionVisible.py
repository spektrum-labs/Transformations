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
    data = data if isinstance(data, (dict, list)) else {}

    if isinstance(data, list):
        devices = data
    elif isinstance(data, dict):
        devices = data.get("data") or data.get("results") or data.get("items") or []
        if not isinstance(devices, list):
            devices = []
    else:
        devices = []

    total_devices = 0
    visible_count = 0
    sample_names = []

    for device in devices:
        if not isinstance(device, dict):
            continue
        if "id" not in device:
            # truncation stub entry, not a real device record
            continue
        total_devices = total_devices + 1
        os_info = device.get("os")
        if isinstance(os_info, dict):
            os_name = os_info.get("name")
            build_number = os_info.get("buildNumber")
            if os_name and build_number:
                visible_count = visible_count + 1
                if len(sample_names) < 3:
                    sample_names.append(f"device {device.get('id')}: {os_name} (build {build_number})")

    is_visible = visible_count > 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_visible:
        sample_text = "; ".join(sample_names) if sample_names else "no samples captured"
        pass_reasons.append(
            f"{visible_count} of {total_devices} devices in the getDevicesDetailed response report a non-empty os.name and os.buildNumber, confirming OS name/build/version is retrievable per device. Examples: {sample_text}."
        )
    else:
        fail_reasons.append(
            f"None of the {total_devices} devices returned by getDevicesDetailed included a populated os.name and os.buildNumber field."
        )
        recommendations.append(
            "Verify the devices-detailed API scope/permissions include OS reporting fields, or check that the Ninja agent is successfully reporting OS inventory data."
        )

    result = {
        "isDeviceOSVersionVisible": is_visible,
        "devicesWithVisibleOs": visible_count,
        "totalDevicesInspected": total_devices,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalDevicesInspected": total_devices, "devicesWithVisibleOs": visible_count},
        metadata={
            "transformationId": "isDeviceOSVersionVisible",
            "vendor": "NinjaOne Endpoint Management",
            "category": "epp",
        },
    )
