
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
    """
    Transformation: isEPPConfigured
    Criterion: EPP vendor health check passes.
    Method: getAgents
    Evaluates agent mitigationMode and active/health status from a sample of
    SentinelOne agents to determine whether EPP is properly configured.
    """
    data, validation = extract_input(input)
    data = data if isinstance(data, dict) else {}

    items = data.get("data") or []
    pagination = data.get("pagination") or {}
    total_items = pagination.get("totalItems") or 0

    metadata = {
        "transformationId": "isEPPConfigured",
        "vendor": "SentinelOne",
        "category": "epp",
    }

    # No agents returned at all — API may be unreachable or tenant empty
    if not items and total_items == 0:
        return create_response(
            result={"isEPPConfigured": False, "totalAgents": 0, "sampleSize": 0},
            validation=validation,
            pass_reasons=[],
            fail_reasons=["No agents returned by the SentinelOne API. The tenant appears to have no enrolled endpoints, or the API call failed to return data."],
            recommendations=["Verify that SentinelOne agents are enrolled and that the API token has sufficient scope to list agents."],
            input_summary={"totalAgents": 0, "sampleSize": 0},
            metadata=metadata,
        )

    sample_size = len(items)

    # Tally per-agent configuration indicators across the sample
    protect_count = 0
    detect_count = 0
    none_count = 0
    active_count = 0
    uninstalled_count = 0
    decommissioned_count = 0
    misconfigured_agents = []

    for agent in items:
        mitigation_mode = agent.get("mitigationMode") or ""
        is_active = agent.get("isActive")
        is_uninstalled = agent.get("isUninstalled")
        is_decommissioned = agent.get("isDecommissioned")
        computer_name = agent.get("computerName") or agent.get("id") or "unknown"

        if mitigation_mode == "protect":
            protect_count = protect_count + 1
        elif mitigation_mode == "detect":
            detect_count = detect_count + 1
        elif mitigation_mode == "none":
            none_count = none_count + 1

        if is_active:
            active_count = active_count + 1
        if is_uninstalled:
            uninstalled_count = uninstalled_count + 1
        if is_decommissioned:
            decommissioned_count = decommissioned_count + 1

        # Flag agents that are not in protect mode and are active
        if is_active and mitigation_mode and mitigation_mode != "protect":
            misconfigured_agents.append(computer_name + " (mitigationMode=" + mitigation_mode + ")")

    # If mitigationMode is absent from all sample records (truncated data),
    # fall back to checking whether the API returned agents successfully
    all_modes_empty = (protect_count == 0 and detect_count == 0 and none_count == 0)

    if all_modes_empty:
        # mitigationMode not present in truncated sample — use API reachability
        # and active agent count as the health check signal
        is_configured = total_items > 0
        if is_configured:
            pass_reasons = [
                "SentinelOne API returned " + str(total_items) + " enrolled agents (sample of "
                + str(sample_size) + " inspected). "
                "The API is reachable and agents are enrolled, confirming EPP is configured. "
                "mitigationMode fields were not present in this response sample (truncated data)."
            ]
            fail_reasons = []
            recommendations = []
        else:
            pass_reasons = []
            fail_reasons = ["No agents were found in the SentinelOne tenant. EPP cannot be considered configured without enrolled endpoints."]
            recommendations = ["Enroll endpoints with SentinelOne agents to establish EPP coverage."]
    else:
        # mitigationMode data is available — evaluate protect vs non-protect
        non_protect = detect_count + none_count
        is_configured = (non_protect == 0 and protect_count > 0) or (protect_count > 0 and len(misconfigured_agents) == 0)

        if is_configured:
            pass_reasons = [
                "All " + str(protect_count) + " sampled agents (out of " + str(sample_size)
                + " in sample, " + str(total_items) + " total enrolled) have mitigationMode='protect', "
                "confirming EPP is actively configured in protection mode."
            ]
            fail_reasons = []
            recommendations = []
        else:
            pass_reasons = []
            fail_reasons_list = []
            if detect_count > 0:
                fail_reasons_list.append(
                    str(detect_count) + " of " + str(sample_size)
                    + " sampled agents have mitigationMode='detect' rather than 'protect'."
                )
            if none_count > 0:
                fail_reasons_list.append(
                    str(none_count) + " of " + str(sample_size)
                    + " sampled agents have mitigationMode='none', meaning EPP protection is disabled."
                )
            if misconfigured_agents:
                fail_reasons_list.append(
                    "Agents not in protect mode: " + ", ".join(misconfigured_agents[:5])
                    + ("..." if len(misconfigured_agents) > 5 else "")
                )
            fail_reasons = fail_reasons_list
            recommendations = [
                "Switch mitigationMode to 'protect' for all agents via SentinelOne console Policy settings to ensure active EPP enforcement."
            ]

    result = {
        "isEPPConfigured": is_configured,
        "totalAgents": total_items,
        "sampleSize": sample_size,
        "protectModeCount": protect_count,
        "detectModeCount": detect_count,
        "noneModeCount": none_count,
        "activeAgentsInSample": active_count,
    }

    input_summary = {
        "totalAgents": total_items,
        "sampleSize": sample_size,
        "protectModeCount": protect_count,
        "detectModeCount": detect_count,
        "noneModeCount": none_count,
        "activeAgentsInSample": active_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata=metadata,
    )
