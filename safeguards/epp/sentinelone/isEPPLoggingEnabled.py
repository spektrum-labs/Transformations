
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
    """
    isEPPLoggingEnabled — checks whether EDR telemetry/logging is active on agents.

    Signal: each agent's activeProtection array contains 'edr' when EDR logging is
    active. A sample page from getAgents is evaluated; if every agent in the sample
    has 'edr' in activeProtection the criterion passes. Agents missing 'edr' are
    flagged individually.
    """
    data, validation = extract_input(input)
    data = data if isinstance(data, dict) else {}

    items = data.get("data") or []
    pagination = data.get("pagination") or {}
    total_items = pagination.get("totalItems") or 0

    sample_size = len(items)

    agents_with_edr = []
    agents_without_edr = []

    for agent in items:
        active_protection = agent.get("activeProtection") or []
        name = agent.get("computerName") or agent.get("id") or "unknown"
        if "edr" in active_protection:
            agents_with_edr.append(name)
        else:
            agents_without_edr.append(name)

    with_edr_count = len(agents_with_edr)
    without_edr_count = len(agents_without_edr)

    if sample_size == 0:
        is_logging_enabled = False
        pass_reasons = []
        fail_reasons = ["No agent records were returned by the API; cannot confirm EDR logging is active."]
        recommendations = ["Verify that the SentinelOne API token has permission to list agents and that agents are enrolled."]
    elif without_edr_count == 0:
        is_logging_enabled = True
        pass_reasons = [
            "All " + str(with_edr_count) + " agents in the sample page have 'edr' present in their activeProtection array, confirming EDR telemetry and logging is active. Fleet total reported by pagination: " + str(total_items) + " agents."
        ]
        fail_reasons = []
        recommendations = []
    else:
        is_logging_enabled = False
        pass_reasons = []
        sample_names = agents_without_edr[:5]
        names_str = ", ".join(sample_names)
        fail_reasons = [
            str(without_edr_count) + " of " + str(sample_size) + " sampled agents are missing 'edr' from their activeProtection array, indicating EDR logging is not active on those endpoints. Examples: " + names_str
        ]
        recommendations = [
            "Review and update the SentinelOne policy assigned to the affected agents to enable EDR telemetry. Ensure the license bundle (Complete or Control) includes EDR for all " + str(total_items) + " enrolled agents."
        ]

    result = {
        "isEPPLoggingEnabled": is_logging_enabled,
        "sampleSize": sample_size,
        "agentsWithEDR": with_edr_count,
        "agentsWithoutEDR": without_edr_count,
        "totalAgentsReported": total_items,
    }

    input_summary = {
        "sampleSize": sample_size,
        "totalItemsFromPagination": total_items,
        "agentsWithEDR": with_edr_count,
        "agentsWithoutEDR": without_edr_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isEPPLoggingEnabled",
            "vendor": "SentinelOne",
            "category": "epp",
        },
    )
