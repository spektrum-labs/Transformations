"""Transformation: isEPPLoggingEnabled
Checks whether EDR logging is active on SentinelOne agents by inspecting
the activeProtection array for the presence of 'edr', which indicates
the agent is streaming detection telemetry / logging.
"""


def transform(api_response):
    api_response = api_response if isinstance(api_response, dict) else {}
    data = api_response.get("data") or []
    pagination = api_response.get("pagination") or {}
    total_items = pagination.get("totalItems") or 0

    agents_with_edr = 0
    total_in_page = len(data)

    for agent in data:
        if isinstance(agent, dict):
            active_protection = agent.get("activeProtection") or []
            if isinstance(active_protection, list) and "edr" in active_protection:
                agents_with_edr += 1

    # Logging is considered enabled if at least one sampled agent has EDR active
    if total_in_page == 0:
        is_logging_enabled = False
    else:
        is_logging_enabled = agents_with_edr > 0

    return {
        "transformedResponse": {
            "isEPPLoggingEnabled": is_logging_enabled,
            "agentsWithEDRLogging": agents_with_edr,
            "agentsSampled": total_in_page,
            "totalAgents": total_items,
        },
        "additionalInfo": {
            "dataCollection": {"status": "success", "errors": []},
            "validation": {"status": "skipped", "errors": [], "warnings": []},
        },
    }
