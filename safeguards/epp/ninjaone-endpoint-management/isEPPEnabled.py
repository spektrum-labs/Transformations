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

    # Build per-device set of product states.
    device_states = {}
    for row in results:
        if not isinstance(row, dict):
            continue
        device_id = row.get("deviceId")
        product_state = row.get("productState")
        if device_id is None:
            continue
        existing = device_states.get(device_id) or []
        existing = existing + [product_state]
        device_states[device_id] = existing

    total_devices = len(device_states)
    devices_with_active_av = 0
    device_ids_active = []
    device_ids_inactive = []
    for device_id, states in device_states.items():
        has_on = False
        for s in states:
            if isinstance(s, str) and s.strip().upper() == "ON":
                has_on = True
                break
        if has_on:
            devices_with_active_av = devices_with_active_av + 1
            device_ids_active.append(device_id)
        else:
            device_ids_inactive.append(device_id)

    is_epp_enabled = total_devices > 0 and devices_with_active_av == total_devices

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if total_devices == 0:
        fail_reasons.append(
            "The antivirus-status report returned zero device rows, so no device could be confirmed to have an AV/EPP product in the ON (enabled) state."
        )
        recommendations.append(
            "Verify the NinjaOne antivirus-status query is scoped to the correct organizations and that agents are reporting AV status."
        )
    elif is_epp_enabled:
        pass_reasons.append(
            f"All {total_devices} device(s) observed in the antivirus-status report have at least one AV/EPP product reporting productState='ON' (e.g. deviceIds sample: {device_ids_active[:5]})."
        )
    else:
        fail_reasons.append(
            f"{len(device_ids_inactive)} of {total_devices} device(s) have no AV/EPP product in productState='ON' in the antivirus-status report (sample inactive deviceIds: {device_ids_inactive[:5]})."
        )
        recommendations.append(
            "Investigate devices with no active AV/EPP product state and enable or reinstall the endpoint protection agent on those endpoints."
        )

    input_summary = {
        "totalDevicesObserved": total_devices,
        "devicesWithActiveAV": devices_with_active_av,
    }

    return create_response(
        result={
            "isEPPEnabled": is_epp_enabled,
            "totalDevicesObserved": total_devices,
            "devicesWithActiveAV": devices_with_active_av,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isEPPEnabled",
            "vendor": "NinjaOne Endpoint Management",
            "category": "epp",
        },
    )
