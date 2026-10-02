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


def measure_offline(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    metadata = {"transformationId": "offlineSensorCount", "vendor": "NinjaOne Endpoint Management", "category": "epp"}
    if validation.get("status") == "failed":
        return unevaluated("offlineSensorCount", "Input validation failed: the device inventory did not match its "
                           "schema, so the offline count is unknown", validation, metadata)
    if isinstance(data, list):
        devices = data
    elif isinstance(data, dict):
        devices = data.get("data") or data.get("devices") or data.get("results") or []
        if not isinstance(devices, list):
            devices = []
    else:
        devices = []
    devices = [d for d in devices if isinstance(d, dict)]
    if not devices:
        return unevaluated("offlineSensorCount", "getDevicesDetailed returned no device records (empty, missing or "
                           "error reply), so the offline count is unknown, not 0", validation, metadata,
                           {"totalDevices": 0})
    readable = [d for d in devices if isinstance(d.get("offline"), bool)]
    if not readable:
        return unevaluated("offlineSensorCount", "None of the " + str(len(devices)) + " device record(s) carries an "
                           "offline flag, so the offline count is unknown", validation, metadata,
                           {"totalDevices": len(devices)})

    total_devices = len(devices)
    offline_count = 0
    offline_names = []
    for d in devices:
        if not isinstance(d, dict):
            continue
        if d.get("offline") is True:
            offline_count = offline_count + 1
            name = d.get("systemName") or d.get("displayName") or str(d.get("id"))
            if len(offline_names) < 5:
                offline_names.append(name)

    sample_str = ", ".join(offline_names) if offline_names else "none"

    pass_reasons = [f"{offline_count} of {total_devices} devices report offline=true in the device inventory returned by getDevicesDetailed (examples: {sample_str})."]
    fail_reasons = []
    recommendations = [f"Investigate offline devices such as {sample_str} to restore connectivity."] if offline_count > 0 else []

    return create_response(
        result={
            "offlineSensorCount": offline_count,
            "totalDevices": total_devices,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalDevices": total_devices, "offlineDevices": offline_count},
        metadata={"transformationId": "offlineSensorCount", "vendor": "NinjaOne Endpoint Management", "category": "epp"},
    )


def parse_body(input):
    """A JSON string or bytes body is parsed; anything else is returned unchanged."""
    if isinstance(input, bytes):
        input = input.decode("utf-8")
    if isinstance(input, str):
        try:
            return json.loads(input)
        except ValueError:
            return None
    return input


def unevaluated(key, reason, validation, metadata, extra=None):
    """Fail closed: the key reads None with the reason in dataCollection.errors, which Token-Service routes to
    Unevaluated (out of the score). An empty, missing or error reply is never a measured 0."""
    result = dict(extra or {})
    result[key] = None
    return create_response(result=result, validation=validation, fail_reasons=[reason], api_errors=[reason],
                           recommendations=["Confirm the NinjaOne API client can read the device inventory for this tenant."],
                           metadata=metadata)


def transform(input):
    metadata = {"transformationId": "offlineSensorCount", "vendor": "NinjaOne Endpoint Management", "category": "epp"}
    try:
        return measure_offline(parse_body(input))
    except Exception as e:  # a transformation never raises into the engine
        return unevaluated("offlineSensorCount", "Transformation error, so the count is unknown: " + str(e),
                           {"status": "error", "errors": [], "warnings": []}, metadata)
