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


def as_int(value):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def is_rfm(value):
    """CrowdStrike reports reduced_functionality_mode as "yes"/"no" (not a boolean), so the old
    `rfm is not True` test counted every RFM sensor as active."""
    return value is True or str(value).strip().lower() in ("yes", "true")


def transform(input):
    """
    requiredCoveragePercentage (CrowdStrike, GET /devices/combined/devices/v1).

    Percentage of returned devices whose sensor is active: status "normal", not in reduced
    functionality mode, an agent_version and a last_seen. Not measured (dataCollection error, shown
    Unevaluated) on an API error, or when the device list is truncated: meta.pagination.total larger
    than the devices returned (an unpaged call returns the first 100), or a merged paginated
    response marked truncated. A percentage of a sample is not the estate's coverage.
    """
    if isinstance(input, bytes):
        input = input.decode("utf-8")
    if isinstance(input, str):
        try:
            input = json.loads(input) if input.strip() else None
        except ValueError:
            input = None
    data, validation = extract_input(input)
    data = data if isinstance(data, dict) else {}

    api_errors = []
    if data.get("error") or data.get("errorType") == "internal" or str(data.get("status", "")).lower() == "error":
        msg = data.get("errorMessage") or data.get("message") or "Unknown API error"
        api_errors.append(f"CrowdStrike API returned an error: {msg}")

    resources = data.get("resources")
    if not isinstance(resources, list):
        resources = []

    meta = data.get("meta") if isinstance(data.get("meta"), dict) else {}
    pagination = meta.get("pagination") if isinstance(meta.get("pagination"), dict) else {}
    reported_total = as_int(pagination.get("total"))
    truncated_flag = pagination.get("truncated") is True or str(pagination.get("truncated")).strip().lower() == "true"
    if not api_errors and ((reported_total is not None and reported_total > len(resources)) or truncated_flag):
        api_errors.append(
            f"Device list was truncated: {len(resources)} of {reported_total if reported_total is not None else 'unknown'} "
            "devices returned; coverage not evaluated on a sample (add pagination to the device method)"
        )

    total = len(resources)
    active = 0
    for device in resources:
        if not isinstance(device, dict):
            continue
        status = device.get("status")
        rfm = device.get("reduced_functionality_mode")
        last_seen = device.get("last_seen")
        agent_version = device.get("agent_version")
        is_active = (
            status == "normal"
            and not is_rfm(rfm)
            and bool(agent_version)
            and bool(last_seen)
        )
        if is_active:
            active = active + 1

    if total > 0:
        percentage = round((active / total) * 100, 2)
    else:
        percentage = 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if api_errors:
        percentage = 0
        fail_reasons.append("Not measured: " + "; ".join(api_errors))
        recommendations.append(
            "Verify the CrowdStrike API credentials (Hosts: Read) and that the device method pages through the "
            "whole estate, then re-run the scan."
        )
    elif total > 0:
        pass_reasons.append(
            f"{active} of {total} known Falcon-managed devices report status='normal', "
            f"reduced_functionality_mode!=true, a populated agent_version, and a recent last_seen "
            f"timestamp, yielding a sensor coverage of {percentage}%."
        )
        if percentage < 100:
            fail_reasons.append(
                f"{total - active} of {total} devices ({round(100 - percentage, 2)}%) do not have "
                f"an actively-reporting Falcon sensor (missing/rfm/stale)."
            )
            recommendations.append(
                "Investigate devices with status != 'normal' or reduced_functionality_mode=true "
                "and reinstall or repair the Falcon sensor to restore full coverage."
            )
    else:
        fail_reasons.append(
            "No device records were returned by getDeviceDetails; coverage percentage could not be computed "
            "(total known devices = 0)."
        )
        recommendations.append(
            "Verify the CrowdStrike Falcon API credentials and device inventory query returned results before "
            "recomputing sensor coverage."
        )

    result = {
        "requiredCoveragePercentage": percentage,
        "activeDevices": active,
        "totalDevices": total,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalDevices": total, "activeDevices": active},
        metadata={
            "transformationId": "requiredCoveragePercentage",
            "vendor": "CrowdStrike Falcon",
            "category": "epp",
        },
        api_errors=api_errors,
    )
