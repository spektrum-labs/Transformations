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

    items = []
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        candidate = data.get("data")
        if isinstance(candidate, list):
            items = candidate
        else:
            candidate2 = data.get("items")
            if isinstance(candidate2, list):
                items = candidate2

    threshold_days = 14
    threshold_seconds = threshold_days * 86400

    epoch = datetime(1970, 1, 1)
    now_ts = (datetime.utcnow() - epoch).total_seconds()

    total_devices = 0
    stale_count = 0
    missing_last_contact = 0
    stale_samples = []

    for d in items:
        if not isinstance(d, dict):
            continue
        total_devices = total_devices + 1
        lc = d.get("lastContact")
        if lc is None:
            missing_last_contact = missing_last_contact + 1
            continue
        lc_val = None
        if isinstance(lc, (int, float)):
            lc_val = float(lc)
        else:
            try:
                lc_val = float(lc)
            except (TypeError, ValueError):
                lc_val = None
        if lc_val is None:
            missing_last_contact = missing_last_contact + 1
            continue
        age_seconds = now_ts - lc_val
        if age_seconds > threshold_seconds:
            stale_count = stale_count + 1
            if len(stale_samples) < 5:
                stale_samples.append({"id": d.get("id"), "lastContact": lc_val, "ageDays": age_seconds / 86400.0})

    result = {
        "staleSensorCount": stale_count,
        "totalDevices": total_devices,
        "staleThresholdDays": threshold_days,
        "missingLastContact": missing_last_contact,
    }

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if total_devices == 0:
        fail_reasons.append("No device records were present in the getDevicesDetailed response to evaluate lastContact staleness.")
        recommendations.append("Verify the getDevicesDetailed integration is returning device records with lastContact timestamps.")
    else:
        if stale_count == 0:
            pass_reasons.append(
                f"All {total_devices} devices reported a lastContact within the {threshold_days}-day staleness threshold."
            )
        else:
            fail_reasons.append(
                f"{stale_count} of {total_devices} devices have a lastContact timestamp older than {threshold_days} days (threshold {threshold_seconds} seconds)."
            )
            recommendations.append(
                "Investigate and re-enroll or troubleshoot connectivity for the stale devices; consider alerting on devices exceeding the 14-day check-in threshold."
            )
        if missing_last_contact > 0:
            fail_reasons.append(
                f"{missing_last_contact} of {total_devices} devices had no parseable lastContact timestamp and were excluded from the stale count."
            )

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalDevices": total_devices,
            "staleCount": stale_count,
            "missingLastContact": missing_last_contact,
        },
        metadata={
            "transformationId": "staleSensorCount",
            "vendor": "NinjaOne Endpoint Management",
            "category": "epp",
        },
    )
