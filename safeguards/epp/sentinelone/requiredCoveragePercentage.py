"""Transformation: requiredCoveragePercentage
Criterion: Coverage percentage of endpoints which Endpoint Security is installed.
Method: getAgents
Every agent record returned by /web/api/v2.1/agents is an endpoint that has the
SentinelOne EPP agent installed. pagination.totalItems gives the total enrolled
count. Since all enrolled endpoints have EPP by definition, coverage = 100 %
when any agents are enrolled, else 0 %.
"""


def transform(api_response):
    api_response = api_response if isinstance(api_response, dict) else {}

    pagination = api_response.get("pagination") or {}
    total_items = pagination.get("totalItems")
    if total_items is None:
        total_items = 0
    try:
        total_items = int(total_items)
    except (TypeError, ValueError):
        total_items = 0

    # All agents visible via getAgents have EPP installed (managed endpoints).
    # Coverage is therefore 100 % when at least one agent is enrolled, else 0 %.
    if total_items > 0:
        coverage_percentage = 100.0
    else:
        coverage_percentage = 0.0

    return {
        "transformedResponse": {
            "requiredCoveragePercentage": coverage_percentage,
            "totalEndpointsWithEPP": total_items,
            "totalEndpointsManaged": total_items,
        },
        "additionalInfo": {
            "dataCollection": {"status": "success", "errors": []},
            "validation": {"status": "skipped", "errors": [], "warnings": []},
        },
    }
