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

    items = data.get("resources") or []
    if not isinstance(items, list):
        items = []

    meta = data.get("meta") or {}
    pagination = meta.get("pagination") or {}
    total_reported = pagination.get("total")
    if not isinstance(total_reported, int):
        total_reported = None

    total_items = len(items)
    total = total_items if total_items > 0 else (total_reported or 0)

    covered = 0
    for device in items:
        if not isinstance(device, dict):
            continue
        policies = device.get("device_policies") or {}
        if not isinstance(policies, dict):
            continue
        prevention = policies.get("prevention") or {}
        if not isinstance(prevention, dict):
            continue
        applied = prevention.get("applied")
        if applied is True:
            covered = covered + 1

    if total > 0:
        percentage = round((covered / total) * 100.0, 2)
    else:
        percentage = 0.0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if total == 0:
        fail_reasons.append(
            "No device records were returned by combinedDevicesV1 (resources list empty and meta.pagination.total absent or zero), so EDR coverage cannot be confirmed."
        )
        recommendations.append(
            "Verify the CrowdStrike Falcon sensor is deployed and devices are enrolled, then re-run the scan."
        )
    elif covered == total:
        pass_reasons.append(
            f"All {total} enrolled devices report device_policies.prevention.applied=true, yielding {percentage}% EDR/prevention policy coverage."
        )
    elif covered > 0:
        pass_reasons.append(
            f"{covered} of {total} enrolled devices report device_policies.prevention.applied=true, yielding {percentage}% EDR/prevention policy coverage."
        )
        fail_reasons.append(
            f"{total - covered} of {total} enrolled devices do not have an applied prevention policy (device_policies.prevention.applied is not true)."
        )
        recommendations.append(
            "Assign an enabled CrowdStrike prevention policy to all remaining hosts to raise EDR coverage toward 100%."
        )
    else:
        fail_reasons.append(
            f"None of the {total} enrolled devices report device_policies.prevention.applied=true; EDR coverage is 0%."
        )
        recommendations.append(
            "Enable and assign a CrowdStrike prevention policy to the device fleet to establish EDR coverage."
        )

    result = {
        "requiredCoveragePercentage": percentage,
        "coveredDevices": covered,
        "totalDevices": total,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalDevices": total, "coveredDevices": covered},
        metadata={
            "transformationId": "requiredCoveragePercentage",
            "vendor": "Crowdstrike",
            "category": "epp",
        },
    )
