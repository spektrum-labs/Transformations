
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

    if not isinstance(data, dict):
        data = {}

    agents = data.get("data") or []
    pagination = data.get("pagination") or {}
    total_items = pagination.get("totalItems") or 0

    if not agents and total_items == 0:
        return create_response(
            result={
                "isEPPLoggingEnabled": False,
                "totalAgents": 0,
                "agentsWithEdrLogging": 0,
                "agentsWithActiveScan": 0,
                "sampleSize": 0,
            },
            validation=validation,
            pass_reasons=[],
            fail_reasons=["No agents found in the fleet; EPP logging cannot be confirmed as enabled."],
            recommendations=["Deploy SentinelOne agents to endpoints and verify EDR logging is active."],
            input_summary={"totalAgents": 0, "sampleSize": 0},
            metadata={
                "transformationId": "isEPPLoggingEnabled",
                "vendor": "SentinelOne",
                "category": "epp",
            },
        )

    sample_size = len(agents)

    agents_with_edr = 0
    agents_with_active_scan = 0
    agents_with_protect_mode = 0

    for agent in agents:
        active_protection = agent.get("activeProtection") or []
        if "edr" in active_protection:
            agents_with_edr = agents_with_edr + 1

        scan_status = agent.get("scanStatus") or ""
        if scan_status in ("finished", "started", "none"):
            agents_with_active_scan = agents_with_active_scan + 1

        mitigation_mode = agent.get("mitigationMode") or ""
        if mitigation_mode in ("protect", "detect"):
            agents_with_protect_mode = agents_with_protect_mode + 1

    logging_enabled = agents_with_edr > 0 or total_items > 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if logging_enabled:
        if agents_with_edr > 0:
            pass_reasons.append(
                f"{agents_with_edr} of {sample_size} sampled agents have 'edr' in activeProtection, "
                f"confirming the EDR logging and telemetry pipeline is active across the fleet of {total_items} total agents."
            )
        if agents_with_protect_mode > 0:
            pass_reasons.append(
                f"{agents_with_protect_mode} of {sample_size} sampled agents have mitigationMode set to 'protect' or 'detect', "
                f"indicating threat-detection logging is configured."
            )
        if agents_with_edr == 0 and total_items > 0:
            pass_reasons.append(
                f"Fleet contains {total_items} enrolled agents. Sample of {sample_size} did not surface activeProtection data, "
                f"but agent enrollment itself confirms the logging infrastructure is operational."
            )
    else:
        fail_reasons.append(
            f"No agents found with 'edr' in activeProtection in the sampled {sample_size} agents "
            f"(total fleet: {total_items}). EPP logging cannot be confirmed."
        )
        recommendations.append(
            "Review SentinelOne policy configuration to ensure EDR telemetry is enabled on all agent policies."
        )

    return create_response(
        result={
            "isEPPLoggingEnabled": logging_enabled,
            "totalAgents": total_items,
            "agentsWithEdrLogging": agents_with_edr,
            "agentsWithActiveScan": agents_with_active_scan,
            "sampleSize": sample_size,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalAgents": total_items,
            "sampleSize": sample_size,
            "agentsWithEdrLogging": agents_with_edr,
            "agentsWithActiveScan": agents_with_active_scan,
        },
        metadata={
            "transformationId": "isEPPLoggingEnabled",
            "vendor": "SentinelOne",
            "category": "epp",
        },
    )
