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

    resources = data.get("resources") or []
    if not isinstance(resources, list):
        resources = []

    meta = data.get("meta") or {}
    if not isinstance(meta, dict):
        meta = {}
    pagination = meta.get("pagination") or {}
    if not isinstance(pagination, dict):
        pagination = {}

    total = pagination.get("total")
    if not isinstance(total, (int, float)):
        total = len(resources)

    resource_count = len(resources)

    transformation_errors = []
    if total and total > 0:
        coverage = (float(resource_count) / float(total)) * 100.0
        if coverage > 100.0:
            coverage = 100.0
    else:
        coverage = 0.0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if total and total > 0:
        pass_reasons.append(
            f"queryDevicesScroll reports {resource_count} device IDs enrolled with the CrowdStrike Falcon "
            f"sensor (EDR/XDR agent) out of meta.pagination.total={int(total)} devices tracked in this "
            f"endpoint inventory, yielding a coverage of {coverage:.1f}%."
        )
    else:
        fail_reasons.append(
            "queryDevicesScroll returned meta.pagination.total=0 (or missing), indicating no devices are "
            "enrolled with a Falcon sensor in this tenant, so EDR/XDR coverage cannot be confirmed."
        )
        recommendations.append(
            "Deploy the CrowdStrike Falcon sensor to endpoints and re-run device enumeration; no devices "
            "were found in the devices-scroll inventory."
        )

    if coverage < 100.0 and total and total > 0:
        recommendations.append(
            f"Only {resource_count} of {int(total)} tracked devices were returned in this scroll page; "
            "verify pagination is followed to completion so the full fleet's Falcon sensor coverage is captured."
        )

    result = {
        "requiredCoveragePercentage": coverage,
        "enrolledDeviceCount": resource_count,
        "totalDeviceCount": int(total) if total else 0,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"resourceCount": resource_count, "total": total},
        metadata={
            "transformationId": "requiredCoveragePercentage",
            "vendor": "Crowdstrike",
            "category": "epp",
        },
        transformation_errors=transformation_errors,
    )
