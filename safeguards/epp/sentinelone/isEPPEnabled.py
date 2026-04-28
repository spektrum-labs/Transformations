"""Transformation: isEPPEnabled
Criterion: Is EPP Enabled
Vendor: SentinelOne
Method: getAgents

EPP is considered enabled if at least one SentinelOne agent is enrolled
(totalItems > 0 from pagination). The presence of enrolled agents confirms
EPP solutions are deployed on endpoints.
"""


def transform(api_response):
    api_response = api_response if isinstance(api_response, dict) else {}

    data = api_response.get("data") or []
    pagination = api_response.get("pagination") or {}
    total_items = pagination.get("totalItems") or 0

    # Count active/decommissioned agents in the current page sample
    active_count = 0
    decommissioned_count = 0
    for agent in data:
        if not isinstance(agent, dict):
            continue
        if agent.get("isActive") is True:
            active_count += 1
        if agent.get("isDecommissioned") is True:
            decommissioned_count += 1

    is_epp_enabled = total_items > 0

    transformed_response = {
        "isEPPEnabled": is_epp_enabled,
        "totalAgents": total_items,
        "agentsInPageSample": len(data),
        "activeAgentsInSample": active_count,
        "decommissionedAgentsInSample": decommissioned_count,
    }

    return {
        "transformedResponse": transformed_response,
        "additionalInfo": {
            "dataCollection": {"status": "success", "errors": []},
            "validation": {"status": "skipped", "errors": [], "warnings": []},
        },
    }
