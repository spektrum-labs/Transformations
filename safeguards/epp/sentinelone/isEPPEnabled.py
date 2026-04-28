"""Transformation: isEPPEnabled — SentinelOne getAgents

EPP is considered enabled when at least one SentinelOne agent is enrolled,
as indicated by pagination.totalItems > 0 or a non-empty data page.
"""


def transform(api_response):
    api_response = api_response if isinstance(api_response, dict) else {}

    pagination = api_response.get("pagination") or {}
    total_items = pagination.get("totalItems") or 0

    data = api_response.get("data") or []

    # EPP is enabled if any agents are registered on the account
    is_epp_enabled = total_items > 0 or len(data) > 0

    return {
        "transformedResponse": {
            "isEPPEnabled": is_epp_enabled,
            "totalAgents": total_items,
            "agentsInPage": len(data),
        },
        "additionalInfo": {
            "dataCollection": {"status": "success", "errors": []},
            "validation": {"status": "skipped", "errors": [], "warnings": []},
        },
    }
