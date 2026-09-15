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

    devices = data.get("devices")
    if not isinstance(devices, list):
        devices = []

    total_devices = len(devices)
    secure_count = 0
    non_secure_count = 0
    unknown_count = 0
    non_secure_samples = []

    for device in devices:
        if not isinstance(device, dict):
            continue
        status = device.get("security_status")
        if status is None:
            unknown_count = unknown_count + 1
            continue
        if isinstance(status, str) and status.upper() == "SECURE":
            secure_count = secure_count + 1
        else:
            non_secure_count = non_secure_count + 1
            if len(non_secure_samples) < 5:
                non_secure_samples.append(f"{device.get('guid', 'unknown')}: {status}")

    known_count = secure_count + non_secure_count

    if known_count == 0:
        state = "UNKNOWN"
    elif non_secure_count == 0:
        state = "COMPLIANT"
    else:
        state = "NON_COMPLIANT"

    input_summary = {
        "totalDevices": total_devices,
        "secureCount": secure_count,
        "nonSecureCount": non_secure_count,
        "unknownCount": unknown_count,
    }

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if state == "COMPLIANT":
        pass_reasons.append(
            f"All {known_count} devices with a known security_status report 'SECURE' out of {total_devices} total devices returned by getDevices."
        )
    elif state == "NON_COMPLIANT":
        fail_reasons.append(
            f"{non_secure_count} of {known_count} devices with a known security_status do not report 'SECURE' (examples: {'; '.join(non_secure_samples)})."
        )
        recommendations.append(
            "Investigate devices with non-SECURE security_status in Lookout MES console and remediate outdated OS versions to bring devices into vulnerability-compliant state."
        )
    else:
        fail_reasons.append(
            f"None of the {total_devices} devices returned a security_status field, so OS update compliance state could not be determined."
        )
        recommendations.append(
            "Verify Lookout MES devices endpoint is returning security_status field data for enrolled devices."
        )

    result = {
        "managedSoftwareUpdateComplianceState": state,
        "totalDevices": total_devices,
        "secureCount": secure_count,
        "nonSecureCount": non_secure_count,
        "unknownCount": unknown_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "managedSoftwareUpdateComplianceState",
            "vendor": "Lookout",
            "category": "mobile-security",
        },
    )
