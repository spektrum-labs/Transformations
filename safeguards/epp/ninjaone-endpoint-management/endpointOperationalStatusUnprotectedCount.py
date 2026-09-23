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
        records = data
    elif isinstance(data, dict):
        records = data.get("results") or data.get("data") or []
        if not isinstance(records, list):
            records = []
    else:
        records = []

    device_protected = {}
    device_seen = {}
    for rec in records:
        if not isinstance(rec, dict):
            continue
        device_id = rec.get("deviceId")
        if device_id is None:
            continue
        device_seen[device_id] = True
        product_state = rec.get("productState")
        product_name = rec.get("productName")
        is_on = product_state == "ON"
        if is_on:
            device_protected[device_id] = True
        else:
            if device_id not in device_protected:
                device_protected[device_id] = False

    total_devices = len(device_seen)
    unprotected_ids = [d for d, protected in device_protected.items() if not protected]
    unprotected_count = len(unprotected_ids)
    protected_count = total_devices - unprotected_count

    sample_ids = unprotected_ids[:10]

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if total_devices == 0:
        fail_reasons.append(
            "Antivirus status report returned no device records; unable to determine unprotected endpoint count."
        )
        recommendations.append(
            "Verify the antivirus status report endpoint is returning data for managed devices."
        )
    else:
        if unprotected_count > 0:
            fail_reasons.append(
                f"{unprotected_count} of {total_devices} devices report no active AV/EPP protection "
                f"(productState != 'ON', or product missing/NONE, or state unreported); example deviceIds: {sample_ids}."
            )
            recommendations.append(
                "Investigate and remediate unprotected devices: reinstall or re-enable the endpoint protection "
                "agent and confirm productState reports 'ON'."
            )
        else:
            pass_reasons.append(
                f"All {total_devices} devices report at least one AV/EPP product with productState='ON'."
            )

    result = {
        "endpointOperationalStatusUnprotectedCount": unprotected_count,
        "totalDevicesReported": total_devices,
        "protectedDeviceCount": protected_count,
    }

    input_summary = {
        "recordsInResponse": len(records),
        "totalDevicesReported": total_devices,
        "unprotectedDeviceCount": unprotected_count,
    }

    metadata = {
        "transformationId": "endpointOperationalStatusUnprotectedCount",
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
