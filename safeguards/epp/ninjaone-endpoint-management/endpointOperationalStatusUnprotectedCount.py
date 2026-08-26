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
        results = data.get("results") or data.get("data") or []
    else:
        results = []

    if not isinstance(results, list):
        results = []

    # Group AV product rows by deviceId, tracking whether any product
    # for that device reports an active/on state.
    device_active = {}
    for row in results:
        if not isinstance(row, dict):
            continue
        device_id = row.get("deviceId")
        if device_id is None:
            continue
        product_state = row.get("productState") or ""
        is_on = isinstance(product_state, str) and product_state.strip().upper() == "ON"
        if device_id not in device_active:
            device_active[device_id] = False
        if is_on:
            device_active[device_id] = True

    total_devices = len(device_active)
    unprotected_devices = [dev_id for dev_id, active in device_active.items() if not active]
    unprotected_count = len(unprotected_devices)

    if total_devices == 0:
        pass_reasons = []
        fail_reasons = ["No antivirus-status records were returned by getAntivirusStatusReport, so no device coverage could be confirmed."]
        recommendations = ["Verify the antivirus-status query endpoint is returning data for the tenant's managed devices."]
    elif unprotected_count == 0:
        pass_reasons = [
            "All %d devices reporting in the antivirus-status feed have at least one product with productState=ON." % total_devices
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        sample_ids = unprotected_devices[:5]
        fail_reasons = [
            "%d of %d devices in the antivirus-status feed report no product with productState=ON (unprotected device IDs include: %s)." % (
                unprotected_count, total_devices, ", ".join([str(x) for x in sample_ids])
            )
        ]
        recommendations = [
            "Investigate and remediate the AV agent on the unprotected devices, e.g. reinstall or re-enable the AV product so productState reports ON."
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
