"""Transformation: isEPPConfigured (SentinelOne, GET /web/api/v2.1/agents).

Value: a whole-number percentage, floor(100 * configured / protected). protected = agents returned (each is an
installed agent, servers included); configured = agents enforcing protection: mitigationMode "protect" (detect-only
does not block) with a non-empty activeProtection list. The pass bar lives in the requirement. Agent last-seen age is
not read, so staleness is never held against an agent. Not evaluated (dataCollection error, no value) when no agent
is returned or when the agent list is a truncated page (pagination.totalItems larger than the agents returned, or a
nextCursor still present): a percentage of a sample is not the fleet's.
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
    # New input format: TS hands {"data": <raw response>, "validation": ...} to a transform that reads
    # input.get("data"), so pagination.totalItems and nextCursor stay visible. The legacy format drills
    # into the bare agent list and would hide a truncated page.
    if isinstance(input, dict) and "validation" in input:
        data, validation = extract_input(input.get("data"))[0], input["validation"]
    else:
        data, validation = extract_input(input)

    # Token-Service preprocessing may unwrap to a bare list of agents (when API
    # response's `data` field is a list) or leave a dict containing `data`/`pagination`.
    next_cursor = None
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
        next_cursor = pagination.get("nextCursor")
    else:
        agents = []
        total_items = 0
    total_items = int(total_items) if total_items else 0

    sampled = len(agents)
    truncated = total_items > sampled or str(next_cursor).strip() not in ("", "None", "null")

    # No agents, or a truncated page: not evaluated (no value), never a percentage of a sample
    if sampled == 0 or truncated:
        reason = (
            f"Agent list is truncated: {sampled} of {total_items} agents returned; configuration not evaluated on a sample"
            if sampled and truncated else "No SentinelOne agents were returned; there is nothing to measure"
        )
        return create_response(
            result={
                "isEPPConfigured": None,
                "totalAgents": total_items,
                "sampledAgents": sampled,
                "protectModeCount": 0,
                "detectModeCount": 0,
                "noneModeCount": 0,
            },
            validation=validation,
            api_errors=[reason],
            fail_reasons=[reason],
            recommendations=[
                "Add pagination to the SentinelOne agents method so every agent is read"
                if sampled else "Deploy SentinelOne agents to endpoints and confirm the siteId setting"
            ],
            input_summary={"totalAgents": total_items, "sampledAgents": sampled},
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

    configured_count = 0
    for agent in agents:
        agent = agent if isinstance(agent, dict) else {}
        active = agent.get("activeProtection")
        if agent.get("mitigationMode") == "protect" and isinstance(active, list) and len(active) > 0:
            configured_count = configured_count + 1
    configured_pct = (configured_count * 100) // sampled
    is_configured = configured_count == sampled

    pass_reasons = []
    fail_reasons = []
    recommendations = []
    additional_findings = []

    summary_line = (
        f"{configured_count} of {sampled} agents ({configured_pct}%) enforce protection "
        f"(mitigationMode 'protect' with activeProtection reported); "
        f"{detect_count} in 'detect', {none_count} in 'none'."
    )
    if is_configured:
        pass_reasons.append(summary_line)
    else:
        fail_reasons.append(summary_line)
        if unconfigured_names:
            additional_findings.append(
                f"Agents without mitigation: {', '.join(unconfigured_names[:5])}"
                f"{'...' if len(unconfigured_names) > 5 else ''}."
            )
        recommendations.append(
            "Set mitigationMode to 'protect' on all agents via the SentinelOne console under Sentinels > Policy. "
            "'detect' only alerts and 'none' provides no active threat mitigation."
        )
    if active_protection_only > 0:
        additional_findings.append(
            f"{active_protection_only} agents had mitigationMode absent but reported activeProtection; "
            f"not counted as enforcing."
        )

    return create_response(
        result={
            "isEPPConfigured": configured_pct,
            "configuredAgents": configured_count,
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
