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

    device_states = {}
    for rec in records:
        if not isinstance(rec, dict):
            continue
        device_id = rec.get("deviceId")
        if device_id is None:
            continue
        product_name = rec.get("productName") or "NONE"
        product_state = rec.get("productState")
        if device_id not in device_states:
            device_states[device_id] = {"has_product": False, "enabled": False}
        if product_name != "NONE":
            device_states[device_id]["has_product"] = True
            if product_state == "ON":
                device_states[device_id]["enabled"] = True

    protected_device_ids = [d for d, s in device_states.items() if s["has_product"]]
    enabled_device_ids = [d for d in protected_device_ids if device_states[d]["enabled"]]

    total_protected = len(protected_device_ids)
    total_enabled = len(enabled_device_ids)

    is_epp_enabled = total_protected > 0 and total_enabled == total_protected

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if total_protected == 0:
        fail_reasons.append(
            "No devices in the antivirus status report have a reporting AV/EPP product (all productName values are 'NONE')."
        )
        recommendations.append(
            "Deploy and enable an endpoint protection product on managed devices so productState can be reported."
        )
    elif is_epp_enabled:
        pass_reasons.append(
            "All %d devices with a reporting AV/EPP product have productState=ON (device ids: %s)." % (
                total_protected, ", ".join([str(d) for d in enabled_device_ids])
            )
        )
    else:
        disabled_ids = [d for d in protected_device_ids if d not in enabled_device_ids]
        fail_reasons.append(
            "%d of %d devices with a reporting AV/EPP product do not have productState=ON (disabled/snoozed/unknown device ids: %s)." % (
                len(disabled_ids), total_protected, ", ".join([str(d) for d in disabled_ids])
            )
        )
        recommendations.append(
            "Investigate and re-enable the AV/EPP product on devices reporting productState=OFF or missing state."
        )

    result = {
        "isEPPEnabled": is_epp_enabled,
        "protectedDeviceCount": total_protected,
        "activeDeviceCount": total_enabled,
    }

    input_summary = {
        "totalRecords": len(records),
        "devicesWithProduct": total_protected,
        "devicesWithProductOn": total_enabled,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isEPPEnabled",
            "vendor": "NinjaOne",
            "category": "epp",
        },
    )
