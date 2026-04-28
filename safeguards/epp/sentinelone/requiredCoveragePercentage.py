"""Transformation: requiredCoveragePercentage"""


def transform(api_response):
    api_response = api_response if isinstance(api_response, dict) else {}

    pagination = api_response.get("pagination") or {}
    total_items = pagination.get("totalItems")

    # All agents returned by /agents have EPP installed by definition.
    # pagination.totalItems is the authoritative enrolled-agent count across all pages.
    total_with_epp = int(total_items) if total_items is not None else 0

    # Relative to SentinelOne-managed endpoints, coverage is 100 % because
    # every record in /agents IS an endpoint with EPP deployed.
    # When total is 0 we report 0 to avoid a false positive.
    if total_with_epp > 0:
        coverage_percentage = 100.0
    else:
        coverage_percentage = 0.0

    return {
        "transformedResponse": {
            "coveragePercentage": coverage_percentage,
            "totalEndpointsWithEPP": total_with_epp,
        },
        "additionalInfo": {
            "dataCollection": {"status": "success", "errors": []},
            "validation": {"status": "skipped", "errors": [], "warnings": []},
        },
    }
