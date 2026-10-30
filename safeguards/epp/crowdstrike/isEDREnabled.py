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

    resources = data.get("resources") or []
    if not isinstance(resources, list):
        resources = []

    meta = data.get("meta") or {}
    pagination = meta.get("pagination") or {}
    total_devices = pagination.get("total")
    if not isinstance(total_devices, int):
        total_devices = len(resources)

    protected_count = 0
    sample_hostnames = []
    for device in resources:
        if not isinstance(device, dict):
            continue
        device_policies = device.get("device_policies") or {}
        prevention = device_policies.get("prevention") or {}
        applied = prevention.get("applied")
        if applied is True:
            protected_count = protected_count + 1
            if len(sample_hostnames) < 3:
                hostname = device.get("hostname") or device.get("device_id") or "unknown"
                sample_hostnames.append(hostname)

    devices_in_page = len(resources)
    is_edr_enabled = protected_count > 0

    input_summary = {
        "devicesInPage": devices_in_page,
        "totalDevices": total_devices,
        "protectedInPage": protected_count,
    }

    if is_edr_enabled:
        sample_str = ", ".join([str(h) for h in sample_hostnames])
        pass_reasons = [
            f"{protected_count} of {devices_in_page} devices in this page report device_policies.prevention.applied=true (examples: {sample_str}), indicating the CrowdStrike EDR/prevention policy is actively applied to endpoints."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"None of the {devices_in_page} devices returned by combinedDevicesV1 (of {total_devices} total enrolled devices) report device_policies.prevention.applied=true."
        ]
        recommendations = [
            "Ensure a CrowdStrike prevention policy is created, enabled, and assigned to host groups covering the enrolled endpoints."
        ]

    result = {
        "isEDREnabled": is_edr_enabled,
        "totalDevices": total_devices,
        "protectedDevices": protected_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isEDREnabled",
            "vendor": "Crowdstrike",
            "category": "epp",
        },
    )
