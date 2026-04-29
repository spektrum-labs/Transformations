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

    pagination = data.get("pagination") or {}
    total_items = pagination.get("totalItems")

    # Fall back to counting items in the data list if pagination is absent
    items = data.get("data") or []
    if total_items is None:
        total_items = len(items)

    total_items = int(total_items) if total_items is not None else 0
    is_epp_enabled = total_items > 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_epp_enabled:
        pass_reasons.append(
            f"SentinelOne EPP agents are deployed on endpoints: pagination.totalItems reports {total_items} enrolled agents across the fleet."
        )
    else:
        fail_reasons.append(
            "No SentinelOne EPP agents were found: pagination.totalItems returned 0, indicating no agents are enrolled on endpoints."
        )
        recommendations.append(
            "Deploy SentinelOne agents on endpoints to enable EPP protection. Install agents via the SentinelOne management console under Sentinels > Endpoints."
        )

    return create_response(
        result={
            "isEPPEnabled": is_epp_enabled,
            "totalAgents": total_items,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalAgents": total_items,
        },
        metadata={
            "transformationId": "isEPPEnabled",
            "vendor": "SentinelOne",
            "category": "epp",
        },
    )
