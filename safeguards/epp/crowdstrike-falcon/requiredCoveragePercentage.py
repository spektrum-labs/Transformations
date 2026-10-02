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
        # Unexpected array root for this endpoint; treat as no envelope info.
        meta = {}
        resources = data
    else:
        meta = data.get("meta") or {}
        resources = data.get("resources") or []
        if not isinstance(resources, list):
            resources = []

    pagination = meta.get("pagination") or {}
    total = pagination.get("total")
    if not isinstance(total, (int, float)):
        total = 0

    sample_count = len(resources)

    transformation_errors = []
    pass_reasons = []
    fail_reasons = []
    recommendations = []
    additional_findings = [
        "Coverage is derived solely from CrowdStrike's own enrolled-device inventory "
        "(queryDevicesByFilter meta.pagination.total). No independent external asset "
        "inventory (e.g. CMDB) source is available in this integration's method "
        "catalogue, so 'known assets' is defined as the set of devices CrowdStrike "
        "Falcon has ever registered a sensor record for."
    ]

    if total > 0:
        percentage = 100.0
        pass_reasons.append(
            f"queryDevicesByFilter reports meta.pagination.total={total} enrolled "
            f"Falcon device records (sample page returned {sample_count} device ids); "
            "every device present in this inventory has an installed Falcon sensor, "
            "so coverage of CrowdStrike's own known asset inventory is 100%."
        )
    else:
        percentage = 0.0
        fail_reasons.append(
            "queryDevicesByFilter returned meta.pagination.total=0 (or missing), "
            "indicating no enrolled devices were found in the Falcon tenant."
        )
        recommendations.append(
            "Verify the CrowdStrike Falcon API credentials and confirm the tenant "
            "has devices enrolled with the Falcon sensor."
        )

    result = {
        "requiredCoveragePercentage": percentage,
        "totalKnownAssets": total,
        "activeSensorCount": total if total > 0 else 0,
        "sampleDeviceCount": sample_count,
    }

    input_summary = {
        "totalKnownAssets": total,
        "sampleDeviceCount": sample_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        additional_findings=additional_findings,
        transformation_errors=transformation_errors,
        metadata={
            "transformationId": "requiredCoveragePercentage",
            "vendor": "CrowdStrike Falcon",
            "category": "epp",
        },
    )
