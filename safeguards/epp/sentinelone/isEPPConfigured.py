"""Transformation: isEPPConfigured"""


def transform(api_response):
    api_response = api_response if isinstance(api_response, dict) else {}

    data = api_response.get("data") or []
    pagination = api_response.get("pagination") or {}
    total_items = pagination.get("totalItems") or 0

    protect_count = 0
    non_protect_count = 0
    for agent in data:
        if not isinstance(agent, dict):
            continue
        mitigation_mode = agent.get("mitigationMode") or ""
        if mitigation_mode == "protect":
            protect_count += 1
        elif mitigation_mode in ("detect", "disabled"):
            non_protect_count += 1

    sample_size = len(data)

    if total_items == 0:
        is_configured = False
    elif sample_size > 0 and (protect_count + non_protect_count) > 0:
        is_configured = protect_count > 0
    else:
        # Agents exist (totalItems > 0) but mitigationMode not visible in sample
        is_configured = total_items > 0

    return {
        "transformedResponse": {
            "isEPPConfigured": is_configured,
            "totalAgents": total_items,
            "protectModeAgents": protect_count,
            "sampleSize": sample_size,
        },
        "additionalInfo": {
            "dataCollection": {"status": "success", "errors": []},
            "validation": {"status": "skipped", "errors": [], "warnings": []},
        },
    }
