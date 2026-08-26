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
        results = data
    elif isinstance(data, dict):
        results = data.get("results") or []
    else:
        results = []

    if not isinstance(results, list):
        results = []

    device_states = {}
    for r in results:
        if not isinstance(r, dict):
            continue
        dev = r.get("deviceId")
        if dev is None:
            continue
        state = r.get("productState")
        if dev not in device_states:
            device_states[dev] = []
        device_states[dev].append(state)

    total_devices = len(device_states)
    unprotected_devices = []
    for dev, states in device_states.items():
        has_on = False
        for s in states:
            if s == "ON":
                has_on = True
                break
        if not has_on:
            unprotected_devices.append(dev)

    unprotected_count = len(unprotected_devices)

    if total_devices == 0:
        pass_reasons = []
        fail_reasons = []
        recommendations = ["No antivirus status records were returned; unable to confirm endpoint protection coverage."]
    elif unprotected_count == 0:
        pass_reasons = [
            "All %d devices reporting to the antivirus-status endpoint have at least one AV product with productState=ON." % total_devices
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        sample = unprotected_devices[:10]
        fail_reasons = [
            "%d of %d devices have no AV product reporting productState=ON (e.g. deviceIds: %s)." % (
                unprotected_count, total_devices, sample
            )
        ]
        recommendations = [
            "Investigate and remediate unprotected endpoints (deviceIds: %s) by enabling or reinstalling their antivirus/EPP agent." % sample
        ]

    result = {
        "endpointOperationalStatusUnprotectedCount": unprotected_count,
        "totalDevicesReporting": total_devices,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalDevicesReporting": total_devices, "unprotectedCount": unprotected_count},
        metadata={
            "transformationId": "endpointOperationalStatusUnprotectedCount",
            "vendor": "NinjaOne Endpoint Management",
            "category": "epp",
        },
    )
