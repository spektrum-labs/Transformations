"""
Transformation: isMDREnabled
Vendor: Red Canary
Category: MDR
Criterion: isMDREnabled — validates that the Red Canary MDR service is active and connected
to the customer environment by confirming enrolled endpoints exist via the /openapi/v3/endpoints API.
"""
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

    # meta.total_items is the authoritative fleet-level count from the API
    total_items = meta.get("total_items")
    if total_items is None:
        # fall back to the length of the returned page if meta is absent
        total_items = len(endpoints)

    total_items = int(total_items) if total_items is not None else 0
    page_count = len(endpoints)

    is_enabled = total_items > 0

    input_summary = {
        "totalEnrolledEndpoints": total_items,
        "endpointsOnPage": page_count,
    }

    if is_enabled:
        pass_reasons = [
            f"Red Canary MDR API returned {total_items} enrolled endpoint(s) "
            f"(meta.total_items={total_items}), confirming the MDR service is active "
            f"and connected to this environment. The /openapi/v3/endpoints API is only "
            f"operational under an active MDR subscription."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            "Red Canary MDR API returned meta.total_items=0 and an empty data array, "
            "indicating no endpoints are enrolled. The MDR service is not active or "
            "no sensors have been deployed to this environment."
        ]
        recommendations = [
            "Deploy the Red Canary sensor to at least one endpoint in the environment "
            "and verify the MDR subscription is active in the Red Canary portal."
        ]

    return create_response(
        result={
            "isMDREnabled": is_enabled,
            "totalEnrolledEndpoints": total_items,
            "endpointsOnPage": page_count,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isMDREnabled",
            "vendor": "Red Canary",
            "category": "MDR",
        },
    )
