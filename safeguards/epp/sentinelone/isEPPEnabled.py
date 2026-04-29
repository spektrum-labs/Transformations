"""Transformation: isEPPEnabled — checks if EPP agents are deployed on endpoints."""

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

    agents = data.get("data") or []
    pagination = data.get("pagination") or {}
    total_items = pagination.get("totalItems") or 0

    active_count = 0
    inactive_count = 0
    decommissioned_count = 0
    uninstalled_count = 0

    for agent in agents:
        if not isinstance(agent, dict):
            continue
        is_active = agent.get("isActive")
        is_decommissioned = agent.get("isDecommissioned")
        is_uninstalled = agent.get("isUninstalled")
        is_pending_uninstall = agent.get("isPendingUninstall")

        if is_decommissioned:
            decommissioned_count = decommissioned_count + 1
        elif is_uninstalled or is_pending_uninstall:
            uninstalled_count = uninstalled_count + 1
        elif is_active:
            active_count = active_count + 1
        else:
            inactive_count = inactive_count + 1

    page_size = len(agents)

    is_epp_enabled = total_items > 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_epp_enabled:
        pass_reasons.append(
            "SentinelOne EPP agents are deployed across the fleet. "
            "pagination.totalItems reports " + str(total_items) + " enrolled agents in the account."
        )
        if page_size > 0:
            pass_reasons.append(
                "Sample of " + str(page_size) + " agents inspected: " +
                str(active_count) + " active, " +
                str(inactive_count) + " inactive, " +
                str(decommissioned_count) + " decommissioned, " +
                str(uninstalled_count) + " uninstalled/pending-uninstall."
            )
    else:
        fail_reasons.append(
            "No SentinelOne EPP agents are enrolled in this account. "
            "pagination.totalItems returned 0, indicating no endpoints have the EPP agent deployed."
        )
        recommendations.append(
            "Deploy the SentinelOne EPP agent to all managed endpoints. "
            "Use the SentinelOne management console to download and distribute the agent installer."
        )

    return create_response(
        result={
            "isEPPEnabled": is_epp_enabled,
            "totalAgents": total_items,
            "activeAgentsInSample": active_count,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalItems": total_items,
            "pageSize": page_size,
            "activeInSample": active_count,
            "inactiveInSample": inactive_count,
            "decommissionedInSample": decommissioned_count,
            "uninstalledInSample": uninstalled_count,
        },
        metadata={
            "transformationId": "isEPPEnabled",
            "vendor": "SentinelOne",
            "category": "epp",
        },
    )
