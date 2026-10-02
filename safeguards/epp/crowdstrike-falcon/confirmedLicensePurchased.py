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
    data = data if isinstance(data, (dict, list)) else {}

    if isinstance(data, list):
        resources = data
        meta = {}
        errors = []
    else:
        resources = data.get("resources") or []
        meta = data.get("meta") or {}
        errors = data.get("errors") or []

    pagination = meta.get("pagination") or {}
    total = pagination.get("total")
    if total is None:
        total = len(resources) if isinstance(resources, list) else 0

    api_errors = []
    if errors:
        api_errors = [str(e) for e in errors]

    has_devices = isinstance(total, (int, float)) and total > 0
    non_empty_response = bool(resources) or has_devices

    confirmed = bool(has_devices and not api_errors)

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if confirmed:
        pass_reasons.append(
            f"queryDevicesByFilter returned a non-empty, authenticated Hosts API response scoped to this "
            f"tenant's CID with meta.pagination.total={total} enrolled sensor device IDs (sample count "
            f"in this page: {len(resources) if isinstance(resources, list) else 0}), confirming an active "
            f"paid Falcon subscription with sensors provisioned against it."
        )
    else:
        fail_reasons.append(
            f"queryDevicesByFilter returned meta.pagination.total={total} with "
            f"{len(resources) if isinstance(resources, list) else 0} device IDs in the response resources array, "
            f"which does not confirm an active provisioned Falcon license."
        )
        recommendations.append(
            "Verify the CrowdStrike Falcon tenant has an active paid subscription and that at least one "
            "sensor has been installed and checked in, then re-run the Hosts API query."
        )

    input_summary = {
        "totalDevices": total,
        "resourcesInResponse": len(resources) if isinstance(resources, list) else 0,
        "apiErrors": api_errors,
    }

    result = {
        "confirmedLicensePurchased": confirmed,
        "totalDevices": total,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        api_errors=api_errors,
        metadata={
            "transformationId": "confirmedLicensePurchased",
            "vendor": "CrowdStrike Falcon",
            "category": "epp",
        },
    )
