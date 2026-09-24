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

    total_records = len(records)
    visible_count = 0
    sample_names = []
    for rec in records:
        if not isinstance(rec, dict):
            continue
        name = rec.get("name")
        device_id = rec.get("deviceId")
        if name and isinstance(name, str) and name.strip() != "" and device_id is not None:
            visible_count = visible_count + 1
            if len(sample_names) < 3:
                sample_names.append(f"deviceId={device_id}: {name}")

    is_visible = total_records > 0 and visible_count == total_records

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if total_records == 0:
        fail_reasons.append(
            "getOperatingSystems returned zero records, so no OS name/version data could be retrieved through the API."
        )
        recommendations.append(
            "Verify devices are enrolled and reporting to NinjaOne, and that the /v2/queries/operating-systems endpoint is reachable."
        )
    elif visible_count == total_records:
        examples = "; ".join(sample_names)
        pass_reasons.append(
            f"All {total_records} device operating-system records returned by getOperatingSystems include a populated 'name' field with OS and version (e.g. {examples})."
        )
    else:
        fail_reasons.append(
            f"Only {visible_count} of {total_records} device operating-system records returned by getOperatingSystems include a populated OS name/version field."
        )
        recommendations.append(
            "Investigate devices missing OS name/version data in the operating-systems report; they may be offline or unable to report inventory."
        )

    result = {
        "isDeviceOSVersionVisible": is_visible,
        "totalDevicesReported": total_records,
        "devicesWithOSVersionVisible": visible_count,
    }

    input_summary = {
        "totalDevicesReported": total_records,
        "devicesWithOSVersionVisible": visible_count,
    }

    validation_out = validation if isinstance(validation, dict) else {"status": "unknown", "errors": [], "warnings": []}

    return create_response(
        result=result,
        validation=validation_out,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isDeviceOSVersionVisible",
            "vendor": "NinjaOne",
            "category": "epp",
        },
    )
