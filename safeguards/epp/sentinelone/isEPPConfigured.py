"""Transformation: isEPPConfigured — checks EPP vendor health by inspecting per-agent mitigationMode fields."""
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

    # Token-Service preprocessing may unwrap to a bare list of agents (when API
    # response's `data` field is a list) or leave a dict containing `data`/`pagination`.
    if isinstance(data, list):
        agents = data
        total_items = len(agents)
    elif isinstance(data, dict):
        agents = data.get("data") or []
        if not isinstance(agents, list):
            agents = []
        pagination = data.get("pagination") or {}
        if not isinstance(pagination, dict):
            pagination = {}
        total_items = pagination.get("totalItems") or len(agents)
    else:
        agents = []
        total_items = 0
    total_items = int(total_items) if total_items else 0

    sampled = len(agents)

    # No agents in fleet — EPP cannot be confirmed configured
    if total_items == 0 and sampled == 0:
        return create_response(
            result={
                "isEPPConfigured": False,
                "totalAgents": 0,
                "sampledAgents": 0,
                "protectModeCount": 0,
                "detectModeCount": 0,
                "noneModeCount": 0,
            },
            validation=validation,
            fail_reasons=["No agents found in the fleet. EPP health check cannot pass with zero enrolled agents."],
            recommendations=[
                "Deploy SentinelOne agents to endpoints. Ensure mitigationMode is set to 'protect' "
                "or 'detect' via the SentinelOne console under Sentinels > Policy."
            ],
            input_summary={"totalAgents": 0, "sampledAgents": 0},
            metadata={
                "transformationId": "isEPPConfigured",
                "vendor": "SentinelOne",
                "category": "epp",
            },
        )

    protect_count = 0
    detect_count = 0
    none_count = 0
    active_protection_only = 0
    unconfigured_names = []

    for agent in agents:
        agent = agent if isinstance(agent, dict) else {}
        mitigation_mode = agent.get("mitigationMode") or ""
        computer_name = agent.get("computerName") or agent.get("uuid") or "unknown"

        if mitigation_mode == "protect":
            protect_count = protect_count + 1
        elif mitigation_mode == "detect":
            detect_count = detect_count + 1
        elif mitigation_mode == "none":
            none_count = none_count + 1
            unconfigured_names.append(computer_name)
        else:
            # mitigationMode absent (e.g. truncated response) — fall back to activeProtection
            active_protection = agent.get("activeProtection") or []
            active_protection = active_protection if isinstance(active_protection, list) else []
            if active_protection:
                active_protection_only = active_protection_only + 1
            else:
                # No mitigation mode and no activeProtection — treat as unconfigured signal
                unconfigured_names.append(computer_name)

    is_configured = total_items > 0 and none_count == 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []
    additional_findings = []

    if is_configured:
        if protect_count > 0 or detect_count > 0:
            pass_reasons.append(
                f"Fleet has {total_items} enrolled agents. Among {sampled} sampled agents, "
                f"{protect_count} are in 'protect' mode and {detect_count} are in 'detect' mode. "
                f"No agents with mitigationMode='none' detected. EPP health check passes."
            )
        else:
            pass_reasons.append(
                f"Fleet has {total_items} enrolled agents. Among {sampled} sampled agents, "
                f"all have active protection reported (activeProtection field populated with active modules). "
                f"No agents with mitigationMode='none' detected. EPP health check passes."
            )
        if active_protection_only > 0:
            additional_findings.append(
                f"{active_protection_only} sampled agents had mitigationMode absent in response "
                f"but reported non-empty activeProtection arrays; counted as configured."
            )
    else:
        fail_reasons.append(
            f"Fleet has {total_items} enrolled agents. Among {sampled} sampled agents, "
            f"{none_count} have mitigationMode='none', indicating EPP mitigation is disabled. "
            f"Affected agents: {', '.join(unconfigured_names[:5])}"
            f"{'...' if len(unconfigured_names) > 5 else ''}."
        )
        recommendations.append(
            "Set mitigationMode to 'protect' or 'detect' on all agents via the SentinelOne console "
            "under Sentinels > Policy. Agents with mitigationMode='none' provide no active threat mitigation."
        )

    return create_response(
        result={
            "isEPPConfigured": is_configured,
            "totalAgents": total_items,
            "sampledAgents": sampled,
            "protectModeCount": protect_count,
            "detectModeCount": detect_count,
            "noneModeCount": none_count,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        additional_findings=additional_findings,
        input_summary={
            "totalAgents": total_items,
            "sampledAgents": sampled,
            "protectModeCount": protect_count,
            "detectModeCount": detect_count,
            "noneModeCount": none_count,
        },
        metadata={
            "transformationId": "isEPPConfigured",
            "vendor": "SentinelOne",
            "category": "epp",
        },
    )
