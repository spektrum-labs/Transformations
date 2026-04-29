"""Transformation: isEPPLoggingEnabled
Checks whether EDR telemetry/logging is active on SentinelOne agents
by inspecting the `activeProtection` array for the 'edr' value.
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

    agents = data.get("data") or []
    pagination = data.get("pagination") or {}
    total_items = pagination.get("totalItems") or 0

    total_agents = len(agents)
    agents_with_edr = 0
    agents_without_edr = []

    for agent in agents:
        active_protection = agent.get("activeProtection") or []
        if "edr" in active_protection:
            agents_with_edr = agents_with_edr + 1
        else:
            computer_name = agent.get("computerName") or agent.get("id") or "unknown"
            agents_without_edr.append(computer_name)

    # Use totalItems from pagination as the authoritative total if available
    effective_total = total_items if total_items > 0 else total_agents

    logging_enabled = (agents_with_edr == total_agents) and (total_agents > 0)

    pass_reasons = []
    fail_reasons = []
    recommendations = []
    additional_findings = []

    if effective_total == 0:
        fail_reasons.append(
            "No agents were returned by the getAgents API. Cannot confirm EDR logging is active."
        )
        recommendations.append(
            "Verify that agents are enrolled in SentinelOne and that the API credentials have sufficient scope to list agents."
        )
    elif logging_enabled:
        pass_reasons.append(
            "All " + str(total_agents) + " agents in the current page have 'edr' present in their activeProtection array, "
            "confirming EDR telemetry and logging is active. The fleet total reported by pagination is " + str(effective_total) + " agents."
        )
        if effective_total > total_agents:
            additional_findings.append(
                "Only " + str(total_agents) + " agents were inspected in this page out of " + str(effective_total) + " total enrolled agents. "
                "Full fleet coverage requires paginated evaluation."
            )
    else:
        agents_missing = total_agents - agents_with_edr
        fail_reasons.append(
            str(agents_missing) + " out of " + str(total_agents) + " inspected agents are missing 'edr' from their activeProtection array, "
            "indicating EDR telemetry/logging is not active on those endpoints."
        )
        if agents_without_edr:
            sample = agents_without_edr[:5]
            additional_findings.append(
                "Sample agents without EDR active: " + ", ".join(sample)
            )
        recommendations.append(
            "Review the SentinelOne policy applied to the affected agents and ensure the EDR module is enabled. "
            "Navigate to Sentinels > Policies, select the relevant policy, and confirm EDR logging is turned on."
        )

    result = {
        "isEPPLoggingEnabled": logging_enabled,
        "totalAgents": effective_total,
        "agentsInspected": total_agents,
        "agentsWithEDRLogging": agents_with_edr,
        "agentsWithoutEDRLogging": total_agents - agents_with_edr,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        additional_findings=additional_findings,
        input_summary={
            "totalItems": effective_total,
            "agentsInspected": total_agents,
            "agentsWithEDR": agents_with_edr,
        },
        metadata={
            "transformationId": "isEPPLoggingEnabled",
            "vendor": "SentinelOne",
            "category": "epp",
        },
    )
