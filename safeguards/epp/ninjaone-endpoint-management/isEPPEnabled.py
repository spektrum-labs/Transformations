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
    results = data.get("results") or []
    if not isinstance(results, list):
        results = []

    # Build per-device protection status: a device is "protected" if at
    # least one antivirus product reporting for it has productState == "ON".
    device_states = {}
    for row in results:
        if not isinstance(row, dict):
            continue
        device_id = row.get("deviceId")
        product_state = row.get("productState")
        if device_id is None:
            continue
        is_on = (product_state == "ON")
        if device_id not in device_states:
            device_states[device_id] = False
        if is_on:
            device_states[device_id] = True

    total_devices = len(device_states)
    protected_devices = 0
    for device_id in device_states:
        if device_states[device_id]:
            protected_devices = protected_devices + 1

    unprotected_devices = total_devices - protected_devices

    is_epp_enabled = (total_devices > 0) and (unprotected_devices == 0)

    input_summary = {
        "totalDevicesReporting": total_devices,
        "protectedDevices": protected_devices,
        "unprotectedDevices": unprotected_devices,
        "totalResultRows": len(results),
    }

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if total_devices == 0:
        fail_reasons.append(
            "No antivirus-status results were returned by the antivirus-status "
            "report, so no device could be confirmed to have an active (productState='ON') "
            "AV/EPP product."
        )
        recommendations.append(
            "Verify that endpoint agents are reporting to the antivirus-status "
            "report endpoint and that at least one AV/EPP product is installed on managed devices."
        )
    elif unprotected_devices == 0:
        sample = []
        count = 0
        for device_id in device_states:
            if count >= 3:
                break
            sample.append(str(device_id))
            count = count + 1
        pass_reasons.append(
            f"All {total_devices} devices with antivirus-status data report at least one "
            f"product with productState='ON' (sample deviceIds: {', '.join(sample)})."
        )
    else:
        unprotected_sample = []
        count = 0
        for device_id in device_states:
            if device_states[device_id]:
                continue
            if count >= 5:
                break
            unprotected_sample.append(str(device_id))
            count = count + 1
        fail_reasons.append(
            f"{unprotected_devices} of {total_devices} devices report productState='OFF' for "
            f"every antivirus product listed (sample unprotected deviceIds: {', '.join(unprotected_sample)})."
        )
        recommendations.append(
            "Investigate devices where all reported antivirus products show productState='OFF' "
            "and re-enable or reinstall the endpoint protection agent."
        )

    result = {
        "isEPPEnabled": is_epp_enabled,
        "totalDevicesReporting": total_devices,
        "protectedDevices": protected_devices,
        "unprotectedDevices": unprotected_devices,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={"transformationId": "isEPPEnabled", "vendor": "NinjaOne Endpoint Management", "category": "epp"},
    )
