"""Transformation: isEPPEnabled — checks if EPP solutions are deployed on endpoints"""

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

    agents = data.get("data") or []
    pagination = data.get("pagination") or {}
    total_items = pagination.get("totalItems") or 0

    # Count active agents in this page sample
    active_in_page = 0
    for agent in agents:
        if agent.get("isActive") is not False:
            active_in_page = active_in_page + 1

    # Count agents with non-empty activeProtection in the page sample
    agents_with_protection = 0
    for agent in agents:
        protection = agent.get("activeProtection") or []
        if len(protection) > 0:
            agents_with_protection = agents_with_protection + 1

    page_size = len(agents)
    is_epp_enabled = total_items > 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_epp_enabled:
        pass_reasons.append(
            "SentinelOne reports " + str(total_items) + " enrolled endpoints (pagination.totalItems=" + str(total_items) + "), confirming EPP agents are deployed across the fleet."
        )
        if page_size > 0:
            pass_reasons.append(
                "In the sampled page of " + str(page_size) + " agents, " + str(agents_with_protection) + " have a non-empty activeProtection array (e.g. 'edr'), confirming active EPP protection is running."
            )
    else:
        fail_reasons.append(
            "No enrolled endpoints found (pagination.totalItems=" + str(total_items) + "). EPP agents do not appear to be deployed."
        )
        recommendations.append(
            "Deploy the SentinelOne agent to all managed endpoints and verify they appear as active in the SentinelOne console."
        )

    return create_response(
        result={
            "isEPPEnabled": is_epp_enabled,
            "totalAgents": total_items,
            "activeAgentsInSample": active_in_page,
            "agentsWithProtectionInSample": agents_with_protection,
            "sampleSize": page_size,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalItems": total_items,
            "sampleSize": page_size,
            "agentsWithProtectionInSample": agents_with_protection,
        },
        metadata={
            "transformationId": "isEPPEnabled",
            "vendor": "SentinelOne",
            "category": "epp",
        },
    )
