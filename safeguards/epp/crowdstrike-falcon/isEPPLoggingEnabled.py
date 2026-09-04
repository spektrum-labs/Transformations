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
    if data.get("error") is True or data.get("statusCode") == 500:
        msg = data.get("errorMessage") or data.get("message") or "Unknown vendor API error"
        api_errors.append(f"Vendor API returned an error: {msg}")

    resources = data.get("resources") or []
    if not isinstance(resources, list):
        resources = []

    meta = data.get("meta") or {}
    pagination = meta.get("pagination") or {}
    total = pagination.get("total")
    if total is None:
        total = len(resources)
    try:
        total = int(total)
    except (TypeError, ValueError):
        total = 0

    is_logging_enabled = total > 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if api_errors:
        fail_reasons.append(
            "Unable to confirm detection logging - the queryDetects API call failed: "
            + "; ".join(api_errors)
        )
        recommendations.append(
            "Verify Falcon API credentials and OAuth scopes (detects:read) and retry the "
            "detection-events query to confirm the Event Streams / detections pipeline is active."
        )
    elif is_logging_enabled:
        pass_reasons.append(
            f"queryDetects returned meta.pagination.total={total} detection record(s), "
            "confirming that prevention/detection events are being generated and are "
            "retrievable via the Falcon detects API (equivalent to an active export/audit trail)."
        )
    else:
        fail_reasons.append(
            "queryDetects returned meta.pagination.total=0 detection records - no evidence "
            "that prevention/detection events are being logged or exported for this tenant."
        )
        recommendations.append(
            "Confirm that the Falcon Event Streams API (or an equivalent SIEM connector) is "
            "configured and that prevention policies are generating detections, then re-run "
            "the scan once detection telemetry is flowing."
        )

    result = {
        "isEPPLoggingEnabled": is_logging_enabled,
        "totalDetections": total,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalDetections": total, "resourceCount": len(resources)},
        metadata={
            "transformationId": "isEPPLoggingEnabled",
            "vendor": "CrowdStrike Falcon",
            "category": "epp",
        },
        api_errors=api_errors,
    )
