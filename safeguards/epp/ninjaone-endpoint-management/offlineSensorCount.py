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

    total_devices = 0
    offline_count = 0
    offline_ids = []
    for d in devices:
        if not isinstance(d, dict):
            continue
        if "_truncated" in d and "offline" not in d:
            continue
        total_devices = total_devices + 1
        if d.get("offline") is True:
            offline_count = offline_count + 1
            if len(offline_ids) < 10:
                offline_ids.append(d.get("id"))

    if total_devices > 0:
        sample_ids = ", ".join([str(i) for i in offline_ids])
        pass_reasons = [
            f"Scanned {total_devices} devices from getDevicesDetailed; found {offline_count} with offline=true (sample ids: {sample_ids})."
        ]
        recommendations = []
        if offline_count > 0:
            recommendations = [
                "Investigate offline devices to determine if they are decommissioned, in transit, or experiencing connectivity/agent issues."
            ]
        fail_reasons = []
    else:
        pass_reasons = []
        fail_reasons = ["No device records were present in the getDevicesDetailed response to evaluate."]
        recommendations = ["Verify the NinjaOne integration is returning device inventory data."]

    result = {
        "offlineSensorCount": offline_count,
        "totalDevices": total_devices,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalDevices": total_devices, "offlineCount": offline_count},
        metadata={
            "transformationId": "offlineSensorCount",
            "vendor": "NinjaOne Endpoint Management",
            "category": "epp",
        },
    )
