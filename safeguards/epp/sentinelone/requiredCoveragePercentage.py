"""Transformation: requiredCoveragePercentage - SentinelOne
Computes the percentage of enrolled endpoints that have Endpoint Security installed
(i.e. not decommissioned, not uninstalled, not pending uninstall).
"""


def transform(api_response):
    if not isinstance(api_response, dict):
        api_response = {}

    data = api_response.get("data")
    if not isinstance(data, list):
        data = []

    pagination = api_response.get("pagination")
    if not isinstance(pagination, dict):
        pagination = {}

    total_items = pagination.get("totalItems")

    # Count agents that have EPP actively installed
    protected_count = 0
    for agent in data:
        if not isinstance(agent, dict):
            continue
        if agent.get("isDecommissioned") or agent.get("isUninstalled") or agent.get("isPendingUninstall"):
            continue
        protected_count += 1

    # Prefer pagination.totalItems as authoritative enrolled count
    if isinstance(total_items, int) and total_items > 0:
        total_enrolled = total_items
    else:
        total_enrolled = len(data)

    if total_enrolled == 0:
        coverage_percentage = None
    else:
        coverage_percentage = round((protected_count / float(total_enrolled)) * 100, 2)

    return {
        "transformedResponse": {
            "coveragePercentage": coverage_percentage,
            "totalAgentsEnrolled": total_enrolled,
            "protectedAgents": protected_count,
        },
        "additionalInfo": {
            "dataCollection": {"status": "success", "errors": []},
            "validation": {"status": "skipped", "errors": [], "warnings": []},
        },
    }
