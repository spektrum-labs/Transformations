"""Transformation: isEPPEnabled -- SentinelOne
Determines whether EPP is enabled by confirming at least one agent is enrolled
in the SentinelOne platform. Uses pagination.totalItems as the authoritative
fleet count (available across all pages, not just the current page).
"""


def transform(api_response):
    api_response = api_response if isinstance(api_response, dict) else {}

    data = api_response.get("data") or []
    pagination = api_response.get("pagination") or {}
    total_items = pagination.get("totalItems")
    if total_items is None:
        total_items = 0

    # Count active agents from the current page sample
    active_count = 0
    for agent in data:
        if isinstance(agent, dict) and agent.get("isActive"):
            active_count += 1

    # EPP is considered enabled when at least one agent is enrolled
    is_epp_enabled = bool(total_items > 0)

    return {
        "transformedResponse": {
            "isEPPEnabled": is_epp_enabled,
            "totalAgents": total_items,
            "activeAgentsInPage": active_count,
        },
        "additionalInfo": {
            "dataCollection": {"status": "success", "errors": []},
            "validation": {"status": "skipped", "errors": [], "warnings": []},
        },
    }
