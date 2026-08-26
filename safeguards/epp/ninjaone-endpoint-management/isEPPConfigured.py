
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
    data = data if isinstance(data, (dict, list)) else []

    if isinstance(data, list):
        devices = data
    elif isinstance(data, dict):
        devices = data.get("data") or data.get("results") or []
        if not isinstance(devices, list):
            devices = []
    else:
        devices = []

    total_devices = len(devices)
    configured_count = 0
    sample_systems = []

    for device in devices:
        if not isinstance(device, dict):
            continue
        policy_id = device.get("policyId")
        has_policy = False
        if isinstance(policy_id, list):
            has_policy = len(policy_id) > 0
        elif isinstance(policy_id, (int, str)):
            has_policy = bool(policy_id)
        if has_policy:
            configured_count = configured_count + 1
            if len(sample_systems) < 5:
                sample_systems.append(device.get("systemName") or str(device.get("id")))

    is_configured = configured_count > 0

    if total_devices == 0:
        fail_reasons = ["No device records were returned by getDevicesDetailed, so EPP policy assignment could not be verified."]
        recommendations = ["Verify NinjaOne device inventory API connectivity and confirm devices are enrolled."]
        pass_reasons = []
    elif is_configured:
        pass_reasons = [
            f"{configured_count} of {total_devices} devices report a non-empty policyId, indicating an endpoint protection policy is assigned. Sample devices: {sample_systems}."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"None of the {total_devices} devices returned by getDevicesDetailed have a policyId assigned (all policyId fields were empty), so no endpoint protection policy is configured on any device."
        ]
        recommendations = [
            "Assign a NinjaOne policy that enables antivirus/EPP settings to each device's organization or device group."
        ]

    result = {
        "isEPPConfigured": is_configured,
        "totalDevices": total_devices,
        "devicesWithAssignedPolicy": configured_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalDevices": total_devices, "devicesWithAssignedPolicy": configured_count},
        metadata={
            "transformationId": "isEPPConfigured",
            "vendor": "NinjaOne",
            "category": "epp",
        },
    )
