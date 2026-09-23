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

    drifted_devices = []
    for rec in records:
        if not isinstance(rec, dict):
            continue
        device_id = rec.get("deviceId")
        overrides = rec.get("overrides") or []
        if isinstance(overrides, list) and len(overrides) > 0:
            drifted_devices.append({"deviceId": device_id, "overrides": overrides})

    drift_count = len(drifted_devices)
    total_records = len(records)

    if drift_count > 0:
        sample = drifted_devices[:5]
        sample_desc = ", ".join(
            [f"device {d['deviceId']} overrides {d['overrides']}" for d in sample]
        )
        pass_reasons = [
            f"Found {drift_count} device(s) with non-empty overriddenSections in the policy-overrides report "
            f"(out of {total_records} device override records returned): {sample_desc}."
        ]
        fail_reasons = []
        recommendations = [
            "Review the listed devices and reconcile device-level policy overrides with the "
            "organization/location default policy, or document why the override is intentional."
        ]
    else:
        pass_reasons = [
            f"No devices with non-empty overriddenSections were found among {total_records} "
            "policy-override records returned by /v2/queries/policy-overrides."
        ]
        fail_reasons = []
        recommendations = []

    input_summary = {
        "totalOverrideRecords": total_records,
        "driftedDeviceCount": drift_count,
    }

    return create_response(
        result={
            "policyOverrideDriftCount": drift_count,
            "totalOverrideRecords": total_records,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "policyOverrideDriftCount",
            "vendor": "NinjaOne",
            "category": "epp",
        },
    )
