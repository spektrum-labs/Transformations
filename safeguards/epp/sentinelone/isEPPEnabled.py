"""Transformation: isEPPEnabled — SentinelOne
Checks whether EPP agents are deployed and active on endpoints.
A deployment is considered enabled when at least one active agent exists
and is not flagged as unprotected.
"""


def transform(response):
    data_collection_errors = []
    validation_warnings = []

    agents = []
    if isinstance(response, dict):
        raw = response.get("data", [])
        if isinstance(raw, list):
            agents = raw
        elif isinstance(raw, dict):
            agents = raw.get("items", [])

    total_agents = len(agents)
    active_agents = 0
    inactive_agents = 0
    unprotected_agents = 0

    for agent in agents:
        is_active = agent.get("isActive", False)
        user_actions = agent.get("userActionsNeeded", [])
        if isinstance(user_actions, list):
            has_unprotected = "unprotected" in user_actions
        else:
            has_unprotected = False

        if is_active and not has_unprotected:
            active_agents += 1
        elif has_unprotected:
            unprotected_agents += 1
        else:
            inactive_agents += 1

    is_epp_enabled = total_agents > 0 and active_agents > 0

    transformed_response = {
        "isEPPEnabled": is_epp_enabled,
        "totalAgents": total_agents,
        "activeAgents": active_agents,
        "inactiveAgents": inactive_agents,
        "unprotectedAgents": unprotected_agents,
    }

    return {
        "transformedResponse": transformed_response,
        "additionalInfo": {
            "dataCollection": {
                "status": "success" if not data_collection_errors else "error",
                "errors": data_collection_errors,
            },
            "validation": {
                "status": "skipped",
                "errors": [],
                "warnings": validation_warnings,
            },
        },
    }
