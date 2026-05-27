
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

    endpoints = data.get("data") or []
    meta = data.get("meta") or {}
    total_items = meta.get("total_items") or 0

    page_count = len(endpoints)
    active_count = 0
    decommissioned_count = 0
    for ep in endpoints:
        attrs = ep.get("attributes") or {}
        is_decommissioned = attrs.get("is_decommissioned")
        if is_decommissioned is True:
            decommissioned_count = decommissioned_count + 1
        else:
            active_count = active_count + 1

    # MDR logging is considered enabled when at least one endpoint is enrolled
    # (meta.total_items > 0 is the fleet-aggregate signal from Red Canary)
    is_enabled = total_items > 0

    if is_enabled:
        pass_reasons = [
            f"Red Canary reports {total_items} enrolled endpoint(s) in meta.total_items, "
            f"confirming that telemetry collection and MDR logging are active for this tenant. "
            f"Page sample: {page_count} endpoint record(s) returned, "
            f"{active_count} not marked as decommissioned."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            "No endpoints are enrolled in Red Canary (meta.total_items=0). "
            "Without enrolled endpoints there is no telemetry flowing into the MDR logging pipeline."
        ]
        recommendations = [
            "Deploy the Red Canary sensor to at least one endpoint and verify it appears "
            "in the /openapi/v3/endpoints response with a non-decommissioned status to confirm "
            "that MDR logging and telemetry forwarding are active."
        ]

    return create_response(
        result={
            "isMDRLoggingEnabled": is_enabled,
            "totalEnrolledEndpoints": total_items,
            "pageEndpointCount": page_count,
            "activeEndpointCount": active_count,
            "decommissionedEndpointCount": decommissioned_count,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalEnrolledEndpoints": total_items,
            "pageEndpointCount": page_count,
        },
        metadata={
            "transformationId": "isMDRLoggingEnabled",
            "vendor": "Red Canary",
            "category": "mdr",
        },
    )
