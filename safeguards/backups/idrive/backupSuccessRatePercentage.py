
import json
from datetime import datetime


CRITERIA_KEY = "backupSuccessRatePercentage"


def error_reason(body):
    """A reason string when the body is an API error or refusal (any 4xx/5xx), else None."""
    if not isinstance(body, dict):
        return None
    for key in ("error", "Error", "errors"):
        err = body.get(key)
        if err:
            return "IDrive API returned an error; " + CRITERIA_KEY + " was not measured."
    for key in ("statusCode", "status_code", "status", "httpStatus"):
        code = body.get(key)
        if isinstance(code, int) and not isinstance(code, bool) and code >= 400:
            return "IDrive API returned HTTP " + str(code) + "; " + CRITERIA_KEY + " was not measured."
    return None


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


FAILURE_STATUSES = ("failure", "failed")
SUCCESS_STATUSES = ("success",)
TRUNCATION_FLAGS = ("paginationTruncated", "iterateTruncated", "itemErrors")


def truncated(body):
    if not isinstance(body, dict):
        return False
    for key in TRUNCATION_FLAGS:
        if body.get(key):
            return True
    return False


def read_devices(input, data):
    """(devices, reason): the getDeviceSummary records, or a reason the read proves nothing.

    Each record must be an object carrying a backup_status key; one that does not makes the whole
    read unreadable, because the count over the rest would look complete when it is not."""
    api_error = error_reason(input) or error_reason(data)
    if api_error:
        return None, api_error
    if truncated(input) or truncated(data):
        return None, "The device summary read was cut short; " + CRITERIA_KEY + " was not measured."
    if isinstance(data, list):
        devices = data
    elif isinstance(data, dict):
        devices = data.get("data")
        if not isinstance(devices, list):
            devices = data.get("devices")
    else:
        devices = None
    if not isinstance(devices, list) or len(devices) == 0:
        return None, "No device records were returned by getDeviceSummary; " + CRITERIA_KEY + " was not measured."
    unreadable = 0
    for dev in devices:
        if not isinstance(dev, dict) or "backup_status" not in dev:
            unreadable = unreadable + 1
        elif dev.get("backup_status") is not None and not isinstance(dev.get("backup_status"), str):
            unreadable = unreadable + 1
    if unreadable > 0:
        return None, (str(unreadable) + " of " + str(len(devices)) + " device record(s) carry no readable backup_status; "
                      + CRITERIA_KEY + " was not measured.")
    return devices, None


def status_of(dev):
    status = dev.get("backup_status")
    return status.strip().lower() if isinstance(status, str) else ""


def evaluate(input):
    data, validation = extract_input(input)
    devices, reason = read_devices(input, data)
    metadata = {"transformationId": CRITERIA_KEY, "vendor": "IDrive", "category": "backup", "source": "getDeviceSummary"}
    if devices is None:
        return create_response(
            result={CRITERIA_KEY: None, "successfulDevices": None, "failedDevices": None, "totalDevices": None},
            validation=validation,
            fail_reasons=[reason],
            recommendations=["Check the IDrive API key and that getDeviceSummary returns every device with its backup_status, then re-run the check."],
            input_summary={"totalDevices": None, "successfulDevices": None, "failedDevices": None, "attempted": None},
            metadata=metadata,
            api_errors=[reason],
        )

    total = len(devices)
    succeeded = len([d for d in devices if status_of(d) in SUCCESS_STATUSES])
    failed = len([d for d in devices if status_of(d) in FAILURE_STATUSES])
    attempted = succeeded + failed
    summary = {"totalDevices": total, "successfulDevices": succeeded, "failedDevices": failed, "attempted": attempted}
    if attempted == 0:
        # A full read with no finished backup to divide by: the rate is not measured, the counts are real.
        reason = ("None of the " + str(total) + " device(s) reports a Success or Failure backup_status; "
                  + CRITERIA_KEY + " was not measured.")
        return create_response(
            result={CRITERIA_KEY: None, "successfulDevices": succeeded, "failedDevices": failed, "totalDevices": total},
            validation=validation,
            fail_reasons=[reason],
            recommendations=["Confirm backups have finished at least once on the company's devices."],
            input_summary=summary,
            metadata=metadata,
            api_errors=[reason],
        )

    rate = round((succeeded / attempted) * 100.0, 2)
    pass_reasons = [str(succeeded) + " of " + str(attempted) + " device(s) with a finished backup report Success, a " + str(rate) + "% success rate."]
    fail_reasons = []
    recommendations = []
    if failed > 0:
        fail_reasons = [str(failed) + " device(s) report a failed last backup (backup_status Failure)."]
        recommendations = ["Investigate the failed devices' backup jobs and re-run them."]

    return create_response(
        result={CRITERIA_KEY: rate, "successfulDevices": succeeded, "failedDevices": failed, "totalDevices": total},
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=summary,
        metadata=metadata,
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
