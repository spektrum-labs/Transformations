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
        devices = data.get("data") or data.get("results") or []
    else:
        devices = []

    total_devices = 0
    offline_count = 0
    offline_names = []
    transform_errors = []

    for d in devices:
        if not isinstance(d, dict):
            continue
        total_devices = total_devices + 1
        if d.get("offline") is True:
            offline_count = offline_count + 1
            name = d.get("systemName") or ("device-%s" % str(d.get("id")))
            if len(offline_names) < 5:
                offline_names.append(name)

    if total_devices == 0:
        pass_reasons = []
        fail_reasons = ["No device records were present in the getDevicesDetailed response; offline count could not be determined."]
        recommendations = ["Verify the NinjaOne getDevicesDetailed integration is returning device inventory data."]
    else:
        sample = ", ".join(offline_names) if offline_names else "none"
        pass_reasons = [
            "Counted %d offline device(s) out of %d total managed devices in getDevicesDetailed (offline=true). Sample offline devices: %s" % (offline_count, total_devices, sample)
        ]
        fail_reasons = []
        recommendations = []
        if offline_count > 0:
            recommendations = ["Investigate offline devices (e.g. %s) to confirm they are decommissioned or restore connectivity." % sample]

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
