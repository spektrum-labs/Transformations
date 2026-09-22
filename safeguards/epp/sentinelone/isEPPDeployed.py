"""
Transformation: isEPPDeployed
Vendor: SentinelOne
Category: epp
Method: getEndpoints

Confirms that the SentinelOne EPP is actually *deployed* — not just enrolled,
but with at least one agent currently active and not uninstalled / decommissioned.
Stricter than isEPPEnabled (which only checks enrollment count).

Pass: at least one enrolled agent has isActive=True, isUninstalled=False,
isDecommissioned=False.
"""
import json
from datetime import datetime, timezone


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
        "evaluatedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
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

    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = data.get("data") or []
        if not isinstance(items, list):
            items = []
    else:
        items = []

    total_enrolled = len(items)
    deployed = 0
    inactive = 0
    uninstalled = 0
    decommissioned = 0

    for agent in items:
        if not isinstance(agent, dict):
            continue
        is_active = bool(agent.get("isActive"))
        is_uninstalled = bool(agent.get("isUninstalled"))
        is_decommissioned = bool(agent.get("isDecommissioned"))

        if is_uninstalled:
            uninstalled = uninstalled + 1
        elif is_decommissioned:
            decommissioned = decommissioned + 1
        elif not is_active:
            inactive = inactive + 1
        else:
            deployed = deployed + 1

    is_deployed = deployed > 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []
    additional_findings = []

    if is_deployed:
        pass_reasons.append(
            f"SentinelOne EPP is deployed: {deployed} of {total_enrolled} enrolled agents "
            f"are currently active, not uninstalled, and not decommissioned."
        )
        if inactive > 0:
            additional_findings.append(
                f"{inactive} enrolled agents are inactive (not currently checking in). "
                f"Investigate any that should be reporting."
            )
    else:
        if total_enrolled == 0:
            fail_reasons.append(
                "No enrolled agents found for the configured site — EPP is not deployed."
            )
        else:
            fail_reasons.append(
                f"None of the {total_enrolled} enrolled agents are actively deployed "
                f"({inactive} inactive, {uninstalled} uninstalled, {decommissioned} decommissioned)."
            )
        recommendations.append(
            "Deploy the SentinelOne agent to managed endpoints. Reactivate any agents "
            "that have stopped reporting and reinstall any that were uninstalled."
        )

    return create_response(
        result={
            "isEPPDeployed": is_deployed,
            "deployedAgents": deployed,
            "totalEnrolledAgents": total_enrolled,
            "inactiveAgents": inactive,
            "uninstalledAgents": uninstalled,
            "decommissionedAgents": decommissioned,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        additional_findings=additional_findings,
        input_summary={
            "totalEnrolledAgents": total_enrolled,
            "deployedAgents": deployed,
            "inactiveAgents": inactive,
            "uninstalledAgents": uninstalled,
            "decommissionedAgents": decommissioned,
        },
        metadata={
            "transformationId": "isEPPDeployed",
            "vendor": "SentinelOne",
            "category": "epp",
        },
    )
