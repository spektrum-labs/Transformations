"""Transformation: requiredCoveragePercentage
Computes the percentage of enrolled SentinelOne agents that are actively covered
(isActive=true) as an indicator of EPP endpoint coverage.
"""


def transform(api_response):
    errors = []
    warnings = []

    # api_response may be a single page dict or a list of page dicts (paginated)
    pages = api_response if isinstance(api_response, list) else [api_response]

    total_agents = 0
    active_agents = 0

    for page in pages:
        data = page.get("data", [])
        if not isinstance(data, list):
            errors.append("Unexpected data format in page; expected list of agent objects.")
            continue
        for agent in data:
            total_agents += 1
            if agent.get("isActive") is True:
                active_agents += 1

    if total_agents == 0:
        coverage_percentage = 0.0
        warnings.append("No agents found; coverage percentage set to 0.")
    else:
        coverage_percentage = round((active_agents / total_agents) * 100, 2)

    transformed_response = {
        "coveragePercentage": coverage_percentage,
        "totalAgents": total_agents,
        "activeAgents": active_agents,
    }

    return {
        "transformedResponse": transformed_response,
        "additionalInfo": {
            "dataCollection": {
                "status": "success" if not errors else "error",
                "errors": errors,
            },
            "validation": {
                "status": "skipped",
                "errors": [],
                "warnings": warnings,
            },
        },
    }
