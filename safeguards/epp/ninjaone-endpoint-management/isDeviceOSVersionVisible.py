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
        devices = data.get("data") or data.get("items") or data.get("results") or []
        if not isinstance(devices, list):
            devices = []
    else:
        devices = []

    total_devices = len(devices)

    devices_with_os_field = [d for d in devices if isinstance(d, dict) and "os" in d and isinstance(d.get("os"), dict)]
    devices_with_populated_os = [
        d for d in devices_with_os_field
        if d.get("os", {}).get("name") and d.get("os", {}).get("buildNumber") is not None
    ]

    total_with_os_field = len(devices_with_os_field)
    total_with_populated_os = len(devices_with_populated_os)

    is_visible = total_with_populated_os > 0

    sample_names = [d.get("os", {}).get("name") for d in devices_with_populated_os[:3]]

    if is_visible:
        pass_reasons = [
            f"{total_with_populated_os} of {total_devices} device records inspected carry a populated os object with name and buildNumber (examples: {sample_names}), confirming the getDevicesDetailed report surfaces OS name/build/version per device."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        if total_devices == 0:
            fail_reasons = ["getDevicesDetailed returned no device records, so OS version visibility could not be confirmed."]
        else:
            fail_reasons = [
                f"None of the {total_devices} device records inspected contained a populated os object with name and buildNumber fields."
            ]
        recommendations = [
            "Verify agent check-in and OS reporting is enabled on managed devices, or confirm the devices-detailed endpoint returns the os object for this tenant."
        ]

    result = {
        "isDeviceOSVersionVisible": is_visible,
        "totalDevices": total_devices,
        "devicesWithOsField": total_with_os_field,
        "devicesWithPopulatedOs": total_with_populated_os,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalDevices": total_devices,
            "devicesWithOsField": total_with_os_field,
            "devicesWithPopulatedOs": total_with_populated_os,
        },
        metadata={
            "transformationId": "isDeviceOSVersionVisible",
            "vendor": "NinjaOne Endpoint Management",
            "category": "epp",
        },
    )
