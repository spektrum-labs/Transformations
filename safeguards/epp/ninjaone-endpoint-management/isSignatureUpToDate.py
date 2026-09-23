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

    up_to_date_devices = []
    out_of_date_devices = []
    unknown_status_devices = []
    devices_without_av = []

    for rec in records:
        if not isinstance(rec, dict):
            continue
        device_id = rec.get("deviceId")
        product_name = rec.get("productName") or ""
        definition_status = rec.get("definitionStatus")

        if product_name == "NONE" or not product_name:
            devices_without_av.append(device_id)
            continue

        if definition_status == "Up-to-Date":
            up_to_date_devices.append(device_id)
        elif definition_status == "Out-of-Date":
            out_of_date_devices.append(device_id)
        else:
            unknown_status_devices.append(device_id)

    total_with_av = len(up_to_date_devices) + len(out_of_date_devices) + len(unknown_status_devices)

    is_up_to_date = total_with_av > 0 and len(out_of_date_devices) == 0

    input_summary = {
        "totalRecords": len(records),
        "devicesWithAV": total_with_av,
        "devicesWithoutAV": len(devices_without_av),
        "upToDateCount": len(up_to_date_devices),
        "outOfDateCount": len(out_of_date_devices),
        "unknownStatusCount": len(unknown_status_devices),
    }

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if total_with_av == 0:
        fail_reasons.append(
            "No devices in the antivirus status report have an installed AV product reporting a definitionStatus; cannot confirm signature currency."
        )
        recommendations.append(
            "Verify antivirus agents are installed and reporting on managed devices so definition status can be evaluated."
        )
    elif is_up_to_date:
        pass_reasons.append(
            "All %d devices with an active antivirus product report definitionStatus='Up-to-Date' (0 out-of-date, %d with unknown status)."
            % (total_with_av, len(unknown_status_devices))
        )
    else:
        fail_reasons.append(
            "%d of %d devices with an active antivirus product report definitionStatus='Out-of-Date' (device IDs: %s)."
            % (len(out_of_date_devices), total_with_av, str(out_of_date_devices))
        )
        recommendations.append(
            "Trigger a definition update / force a signature sync on the out-of-date devices, or investigate why the AV product is not receiving updates."
        )

    result = {
        "isSignatureUpToDate": is_up_to_date,
        "devicesWithAV": total_with_av,
        "upToDateCount": len(up_to_date_devices),
        "outOfDateCount": len(out_of_date_devices),
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isSignatureUpToDate",
            "vendor": "NinjaOne",
            "category": "epp",
        },
    )
