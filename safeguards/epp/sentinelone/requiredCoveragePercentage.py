"""Transformation: requiredCoveragePercentage
Computes the coverage percentage of endpoints with Endpoint Security installed.
Uses pagination.totalItems from getAgents as the total enrolled agent count.
All agents enrolled in SentinelOne have the EPP agent installed by definition.
"""


def transform(api_response):
    api_response = api_response if isinstance(api_response, dict) else {}

    pagination = api_response.get("pagination") or {}
    total_agents = pagination.get("totalItems")
    if total_agents is None:
        total_agents = 0
    total_agents = int(total_agents)

    # Every agent enrolled in SentinelOne has the EPP agent installed.
    # Coverage = enrolled agents with EPP / total enrolled agents = 100%
    # If no agents are enrolled at all, coverage is 0.
    if total_agents > 0:
        coverage_percentage = 100.0
    else:
        coverage_percentage = 0.0

    return {
        "transformedResponse": {
            "coveragePercentage": coverage_percentage,
            "totalAgentsEnrolled": total_agents,
        },
        "additionalInfo": {
            "dataCollection": {"status": "success", "errors": []},
            "validation": {"status": "skipped", "errors": [], "warnings": []},
        },
    }
