"""Transformation: isEPPConfigured
Criterion: EPP vendor health check passes
Method: getAgents
"""


def transform(api_response):
    errors = []
    warnings = []

    data_collection_status = "success"
    validation_status = "skipped"

    is_configured = False
    total_agents = 0
    active_agents = 0
    misconfigured_agents = 0
    misconfiguration_reasons = []

    MISCONFIGURED_STATES = [
        "unprotected",
        "user_action_needed_fda",
        "user_action_needed_network",
        "user_action_needed_rs_fda",
    ]

    try:
        raw = api_response if api_response is not None else {}
        data = raw.get("data") if raw else []
        if data is None:
            data = []

        for agent in data:
            total_agents = total_agents + 1
            is_active = agent.get("isActive", False)
            detection_state = agent.get("detectionState") or ""
            user_actions = agent.get("userActionsNeeded") or []

            agent_misconfigured = False
            reasons = []

            if is_active:
                active_agents = active_agents + 1

            if detection_state in MISCONFIGURED_STATES:
                agent_misconfigured = True
                reasons.append(detection_state)

            for action in user_actions:
                if action in MISCONFIGURED_STATES:
                    if action not in reasons:
                        reasons.append(action)
                    agent_misconfigured = True

            if agent_misconfigured:
                misconfigured_agents = misconfigured_agents + 1
                for r in reasons:
                    if r not in misconfiguration_reasons:
                        misconfiguration_reasons.append(r)

        if total_agents > 0 and misconfigured_agents == 0:
            is_configured = True
        elif total_agents == 0:
            is_configured = False
            warnings.append("No agents found; cannot confirm EPP is configured")

    except Exception as e:
        data_collection_status = "failure"
        errors.append(str(e))
        is_configured = False

    transformed_response = {
        "isEPPConfigured": is_configured,
        "totalAgents": total_agents,
        "activeAgents": active_agents,
        "misconfiguredAgents": misconfigured_agents,
        "misconfigurationReasons": misconfiguration_reasons,
    }

    return {
        "transformedResponse": transformed_response,
        "additionalInfo": {
            "dataCollection": {
                "status": data_collection_status,
                "errors": errors,
            },
            "validation": {
                "status": validation_status,
                "errors": [],
                "warnings": warnings,
            },
        },
    }
