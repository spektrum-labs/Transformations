"""Transformation: isEPPLoggingEnabled"""

def transform(api_response):
    api_response = api_response if isinstance(api_response, dict) else {}
    data = api_response.get("data") or []
    pagination = api_response.get("pagination") or {}
    total_items = pagination.get("totalItems") or 0

    agents_with_logging = 0
    agents_without_logging = 0

    for agent in data:
        if not isinstance(agent, dict):
            continue
        active_protection = agent.get("activeProtection") or []
        if "edr" in active_protection:
            agents_with_logging += 1
        else:
            agents_without_logging += 1

    total_sampled = agents_with_logging + agents_without_logging

    # Logging is considered enabled if there are agents and all sampled agents have EDR active
    if total_sampled == 0:
        is_enabled = False
    else:
        is_enabled = (agents_without_logging == 0 and agents_with_logging > 0)

    return {
        "transformedResponse": {
            "isEPPLoggingEnabled": is_enabled,
            "agentsWithLoggingEnabled": agents_with_logging,
            "agentsWithoutLoggingEnabled": agents_without_logging,
            "totalAgents": total_items,
        },
        "additionalInfo": {
            "dataCollection": {"status": "success", "errors": []},
            "validation": {"status": "skipped", "errors": [], "warnings": []}
        }
    }
