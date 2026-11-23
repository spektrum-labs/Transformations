import json
from datetime import datetime


CRITERIA_KEY = "isJobExecutionLogAccessible"


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
    # Value-keyed: the verdict is measured only when the criterion carries a value. None means
    # the body proved nothing (empty, refusal, missing field, transform raised) and must not be graded.
    value = result.get(CRITERIA_KEY) if isinstance(result, dict) else None
    measured = value is not None
    api_err_list = [] if measured else (api_errors or transformation_errors or fail_reasons
                                        or [CRITERIA_KEY + " could not be measured from the response"])
    transform_err_list = transformation_errors or []
    data_collection_status = "success" if measured else "error"
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


def evaluate(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    if isinstance(data, list):
        devices = data
    elif isinstance(data, dict):
        devices = data.get("data") or data.get("apiResponse") or []
        if not isinstance(devices, list):
            devices = []
    else:
        devices = []

    total_devices = len(devices)
    accessible_count = 0
    sample_device = None
    required_fields = ["backup_status", "last_backup", "next_backup"]

    for d in devices:
        if not isinstance(d, dict):
            continue
        has_all = True
        for f in required_fields:
            val = d.get(f)
            if val is None or val == "":
                has_all = False
                break
        if has_all:
            accessible_count = accessible_count + 1
            if sample_device is None:
                sample_device = d

    is_accessible = total_devices > 0 and accessible_count == total_devices
    if total_devices == 0:
        # No devices: no per-job execution field could be verified, so not measured.
        is_accessible = None

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if total_devices == 0:
        fail_reasons.append("Device summary endpoint returned no devices, so no per-job execution log fields could be verified.")
        recommendations.append("Verify companyId setting and confirm at least one device is enrolled in IDrive 360 before re-evaluating this criterion.")
    elif is_accessible:
        ex = sample_device or {}
        pass_reasons.append(
            f"All {total_devices} device(s) expose per-job execution fields: backup_status='{ex.get('backup_status')}', "
            f"last_backup='{ex.get('last_backup')}', next_backup='{ex.get('next_backup')}' (example device_id={ex.get('device_id')})."
        )
    else:
        fail_reasons.append(
            f"Only {accessible_count} of {total_devices} device(s) carry a complete set of backup_status/last_backup/next_backup fields."
        )
        recommendations.append("Investigate devices missing backup_status, last_backup, or next_backup values in the device summary response.")

    result = {
        "isJobExecutionLogAccessible": is_accessible,
        "totalDevices": total_devices,
        "devicesWithAccessibleLog": accessible_count,
    }

    input_summary = {
        "totalDevices": total_devices,
        "devicesWithAccessibleLog": accessible_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isJobExecutionLogAccessible",
            "vendor": "IDrive",
            "category": "backup",
        },
    )


def transform(input):
    try:
        return evaluate(input)
    except Exception as e:
        return create_response(
            result={CRITERIA_KEY: None},
            fail_reasons=["Transformation error: " + str(e)],
            transformation_errors=["Transformation error: " + str(e)],
            metadata={"transformationId": CRITERIA_KEY, "vendor": "IDrive", "category": "backup"},
        )
