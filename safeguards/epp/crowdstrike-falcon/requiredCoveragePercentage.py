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

    api_errors = []
    if data.get("error") or data.get("errorType") == "internal":
        msg = data.get("errorMessage") or data.get("message") or "Unknown API error"
        api_errors.append(f"CrowdStrike API returned an error: {msg}")

    resources = data.get("resources")
    if not isinstance(resources, list):
        resources = []

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
            and rfm is not True
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

    if total > 0:
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
