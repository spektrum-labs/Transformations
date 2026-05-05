"""Transformation: isMDREnabled — Red Canary MDR enabled check via getEndpoints."""
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

    # Prefer meta.total_items as the authoritative fleet count; fall back to len(endpoints)
    total_items = meta.get("total_items")
    if total_items is None:
        total_items = len(endpoints)

    page_count = len(endpoints)
    is_mdr_enabled = total_items > 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_mdr_enabled:
        pass_reasons.append(
            f"Red Canary MDR is active: meta.total_items={total_items} endpoint(s) are enrolled "
            f"in the tenant. {page_count} endpoint(s) returned on this page confirm the MDR "
            "service is connected and monitoring the environment."
        )
    else:
        fail_reasons.append(
            "Red Canary MDR returned 0 endpoints (meta.total_items=0). No endpoints are enrolled "
            "in this tenant, which indicates MDR monitoring is not active."
        )
        recommendations.append(
            "Enroll at least one endpoint in the Red Canary MDR platform to confirm the service "
            "is operating against the customer environment. Contact Red Canary support to verify "
            "tenant connectivity and sensor deployment."
        )

    return create_response(
        result={
            "isMDREnabled": is_mdr_enabled,
            "totalEndpoints": total_items,
            "pageEndpoints": page_count,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalEndpoints": total_items,
            "pageEndpoints": page_count,
            "metaApiVersion": meta.get("api_version"),
        },
        metadata={
            "transformationId": "isMDREnabled",
            "vendor": "Red Canary",
            "category": "mdr",
        },
    )
