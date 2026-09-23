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
        devices = data.get("data") or data.get("devices") or data.get("results") or []
        if not isinstance(devices, list):
            devices = []
    else:
        devices = []

    total_devices = len(devices)
    offline_devices = [d for d in devices if isinstance(d, dict) and d.get("offline") is True]
    offline_count = len(offline_devices)

    sample_names = [d.get("systemName") or d.get("displayName") or str(d.get("id")) for d in offline_devices[:5]]

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if total_devices == 0:
        fail_reasons.append("No device records were returned by getDevices; unable to determine offline sensor count.")
        recommendations.append("Verify the NinjaOne API credentials and device inventory are accessible.")
    else:
        if offline_count > 0:
            fail_reasons.append(
                f"{offline_count} of {total_devices} managed devices report offline=true (examples: {', '.join([str(n) for n in sample_names])})."
            )
            recommendations.append(
                "Investigate offline devices to confirm whether the NinjaOne agent has stopped checking in beyond the acceptable window, and remediate connectivity or agent health issues."
            )
        else:
            pass_reasons.append(
                f"All {total_devices} managed devices report offline=false; no offline sensors detected."
            )

    result = {
        "offlineSensorCount": offline_count,
        "totalDevices": total_devices,
    }

    input_summary = {
        "totalDevices": total_devices,
        "offlineDevices": offline_count,
    }

    metadata = {
        "transformationId": "offlineSensorCount",
        "vendor": "NinjaOne",
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
