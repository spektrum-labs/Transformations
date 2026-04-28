"""Transformation: isEPPConfigured"""


def transform(api_response):
    api_response = api_response if isinstance(api_response, dict) else {}

    data = api_response.get("data") or []
    pagination = api_response.get("pagination") or {}
    total_agents = pagination.get("totalItems") or 0

    protect_count = 0
    detect_count = 0
    agents_with_mode = 0

    for agent in data:
        if not isinstance(agent, dict):
            continue
        mitigation_mode = agent.get("mitigationMode")
        if mitigation_mode is not None:
            agents_with_mode += 1
            if mitigation_mode == "protect":
                protect_count += 1
            elif mitigation_mode == "detect":
                detect_count += 1

    # EPP is configured if agents are enrolled and operating in protect mode.
    # If the sampled page carries no mitigationMode fields (truncated response),
    # fall back to agent-presence as the signal.
    if agents_with_mode > 0:
        is_configured = protect_count > 0
    else:
        is_configured = total_agents > 0

    return {
        "transformedResponse": {
            "isEPPConfigured": is_configured,
            "totalAgents": total_agents,
            "protectModeCount": protect_count,
            "detectModeCount": detect_count,
        },
        "additionalInfo": {
            "dataCollection": {"status": "success", "errors": []},
            "validation": {"status": "skipped", "errors": [], "warnings": []},
        },
    }
