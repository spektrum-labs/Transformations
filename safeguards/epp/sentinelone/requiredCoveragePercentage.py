"""Transformation: requiredCoveragePercentage — SentinelOne getAgents
Computes the percentage of enrolled endpoints on which the SentinelOne EPP
agent is actively running, using pagination.totalItems as the fleet total.
"""
import json
from datetime import datetime


def extract_input(input_data):
    """Extract data and validation from input, handling enriched + legacy formats."""
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for _ in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    validation = {
        "status": "unknown",
        "errors": [],
        "warnings": ["Legacy input format - no schema validation performed"],
    }
    return data, validation


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None,
                    transformation_errors=None, api_errors=None, additional_findings=None):
    """Create the standardized 5-section transformation response."""
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    transform_err_list = transformation_errors or []
    data_collection_status = "error" if api_err_list else "success"
    transformation_status = "error" if transform_err_list else "success"
    response_metadata = {
        "evaluatedAt": datetime.utcnow().isoformat() + "Z",
        "schemaVersion": "2.0",
    }
    if metadata:
        response_metadata.update(metadata)
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": data_collection_status, "errors": api_err_list},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": transformation_status,
                "errors": transform_err_list,
                "inputSummary": input_summary or {},
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or [],
            },
            "metadata": response_metadata,
        },
    }


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, dict) else {}

    items = data.get("data") or []
    pagination = data.get("pagination") or {}

    total_items = pagination.get("totalItems")
    if total_items is None:
        total_items = len(items)

    total_items = int(total_items) if total_items is not None else 0

    # Count active, non-decommissioned, non-uninstalled agents in the current page
    active_count = 0
    for agent in items:
        is_active = agent.get("isActive")
        is_decommissioned = agent.get("isDecommissioned")
        is_uninstalled = agent.get("isUninstalled")
        is_pending_uninstall = agent.get("isPendingUninstall")
        if (is_active is True
                and is_decommissioned is not True
                and is_uninstalled is not True
                and is_pending_uninstall is not True):
            active_count = active_count + 1

    page_size = len(items)

    # Coverage percentage: active agents over total enrolled fleet
    if total_items == 0:
        coverage_percentage = None
        passes = False
        pass_reasons = []
        fail_reasons = ["No agents are enrolled in SentinelOne (pagination.totalItems=0). Cannot compute coverage."]
        recommendations = ["Ensure the SentinelOne agent is deployed to all managed endpoints."]
    else:
        coverage_percentage = round((active_count * 100.0) / total_items, 2)
        passes = coverage_percentage >= 95.0

        total_str = str(total_items)
        active_str = str(active_count)
        pct_str = str(coverage_percentage)

        if passes:
            pass_reasons = [
                "SentinelOne reports " + total_str + " total enrolled agents (pagination.totalItems=" + total_str + "). "
                + active_str + " agents on the current page are active, non-decommissioned, and not pending uninstall. "
                + "Computed coverage " + pct_str + "% meets or exceeds the 95% threshold."
            ]
            fail_reasons = []
            recommendations = []
        else:
            pass_reasons = []
            fail_reasons = [
                "Coverage is " + pct_str + "% (" + active_str + " active agents out of " + total_str + " total enrolled). "
                + "This is below the required 95% threshold."
            ]
            recommendations = [
                "Deploy the SentinelOne agent to all unprotected endpoints. "
                + "Review agents with isActive=false, isDecommissioned=true, or isPendingUninstall=true and remediate."
            ]

    result = {
        "requiredCoveragePercentage": coverage_percentage,
        "passes": passes,
        "totalAgents": total_items,
        "activeAgentsInPage": active_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalAgents": total_items,
            "activeAgentsInPage": active_count,
            "coveragePercentage": coverage_percentage,
        },
        metadata={
            "transformationId": "requiredCoveragePercentage",
            "vendor": "SentinelOne",
            "category": "epp",
        },
    )
