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

    devices = data.get("devices") or []
    if not isinstance(devices, list):
        devices = []

    total_devices = len(devices)
    activated_devices = [
        d for d in devices
        if isinstance(d, dict) and d.get("activation_status") == "ACTIVATED"
    ]
    activated_count = len(activated_devices)

    protected_devices = [
        d for d in activated_devices
        if d.get("protection_status") == "PROTECTED" and d.get("security_status") == "SECURE"
    ]
    protected_count = len(protected_devices)

    unprotected_devices = [
        d for d in activated_devices
        if d.get("protection_status") not in (None, "PROTECTED") or d.get("security_status") not in (None, "SECURE")
    ]
    unprotected_count = len(unprotected_devices)

    if activated_count == 0:
        is_enabled = False
        fail_reasons = [
            f"No activated devices found among {total_devices} total devices returned by getDevices; "
            "Lookout's on-device network/MITM protection module cannot be confirmed active."
        ]
        pass_reasons = []
        recommendations = [
            "Ensure devices are enrolled and activated in Lookout Mobile Endpoint Security so protection state can be verified."
        ]
    elif protected_count == activated_count:
        is_enabled = True
        pass_reasons = [
            f"All {activated_count} activated devices (of {total_devices} total) report protection_status='PROTECTED' "
            f"and security_status='SECURE', indicating Lookout's on-device network/MITM protection module is active on the fleet."
        ]
        fail_reasons = []
        recommendations = []
    else:
        is_enabled = False
        pass_reasons = []
        fail_reasons = [
            f"{unprotected_count} of {activated_count} activated devices do not report protection_status='PROTECTED' "
            "and security_status='SECURE', indicating Lookout's network/MITM protection module is not confirmed active on all devices."
        ]
        recommendations = [
            "Investigate activated devices whose protection_status is not 'PROTECTED' or security_status is not 'SECURE' "
            "and ensure the Lookout app is running with network protection enabled."
        ]

    result = {
        "isMitmProtectionEnabled": is_enabled,
        "totalDevices": total_devices,
        "activatedDevices": activated_count,
        "protectedDevices": protected_count,
    }

    input_summary = {
        "totalDevices": total_devices,
        "activatedDevices": activated_count,
        "protectedDevices": protected_count,
        "unprotectedDevices": unprotected_count,
    }

    metadata = {
        "transformationId": "isMitmProtectionEnabled",
        "vendor": "Lookout",
        "category": "mobile-security",
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
