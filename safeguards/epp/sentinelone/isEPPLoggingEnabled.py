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
    agents_without_edr = 0
    sample_without_edr = []

    for agent in agents:
        active_protection = agent.get("activeProtection") or []
        if "edr" in active_protection:
            agents_with_edr = agents_with_edr + 1
        else:
            agents_without_edr = agents_without_edr + 1
            computer_name = agent.get("computerName") or agent.get("id") or "unknown"
            if len(sample_without_edr) < 5:
                sample_without_edr.append(computer_name)

    logging_enabled = agents_with_edr > 0 and agents_without_edr == 0

    if total_agents == 0:
        return create_response(
            result={
                "isEPPLoggingEnabled": False,
                "totalAgents": 0,
                "agentsWithEDRLogging": 0,
                "agentsWithoutEDRLogging": 0,
            },
            validation=validation,
            pass_reasons=[],
            fail_reasons=["No agent records were returned; cannot confirm EDR logging is enabled."],
            recommendations=["Ensure SentinelOne agents are enrolled and the API token has permission to list agents."],
            input_summary={"totalAgents": 0, "totalItemsInFleet": total_items},
            metadata={
                "transformationId": "isEPPLoggingEnabled",
                "vendor": "SentinelOne",
                "category": "epp",
            },
        )

    if logging_enabled:
        pass_reasons = [
            f"All {agents_with_edr} of {total_agents} sampled agents (fleet total: {total_items}) "
            f"have 'edr' present in their activeProtection array, confirming EDR telemetry/logging is active."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"{agents_without_edr} of {total_agents} sampled agents are missing 'edr' in their "
            f"activeProtection array, indicating EDR logging is not fully active across the fleet."
        ]
        if sample_without_edr:
            sample_str = ", ".join(sample_without_edr)
            fail_reasons.append(f"Sample agents without EDR logging: {sample_str}")
        recommendations = [
            "Review and update the SentinelOne policy for affected agents to enable EDR telemetry "
            "(ensure the agent policy has 'Deep Visibility' or EDR logging activated)."
        ]

    return create_response(
        result={
            "isEPPLoggingEnabled": logging_enabled,
            "totalAgents": total_agents,
            "agentsWithEDRLogging": agents_with_edr,
            "agentsWithoutEDRLogging": agents_without_edr,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalAgentsSampled": total_agents,
            "totalItemsInFleet": total_items,
            "agentsWithEDR": agents_with_edr,
            "agentsWithoutEDR": agents_without_edr,
        },
        metadata={
            "transformationId": "isEPPLoggingEnabled",
            "vendor": "SentinelOne",
            "category": "epp",
        },
    )
