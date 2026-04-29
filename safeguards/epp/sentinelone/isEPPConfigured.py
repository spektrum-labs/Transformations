
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
    total_items = pagination.get("totalItems") or 0

    total_agents = total_items
    sample_count = len(items)

    # If no agents enrolled at all, EPP is not configured
    if total_agents == 0 and sample_count == 0:
        return create_response(
            result={
                "isEPPConfigured": False,
                "totalAgents": 0,
                "sampleAgentsChecked": 0,
                "agentsInProtectMode": 0,
                "agentsInDetectMode": 0,
                "agentsInNoneMode": 0,
            },
            validation=validation,
            pass_reasons=[],
            fail_reasons=["No enrolled agents found (totalItems=0). EPP is not configured."],
            recommendations=["Deploy the SentinelOne agent to endpoints and set mitigationMode to 'protect' or 'detect'."],
            input_summary={"totalAgents": 0, "sampleAgentsChecked": 0},
            metadata={
                "transformationId": "isEPPConfigured",
                "vendor": "SentinelOne",
                "category": "epp",
            },
        )

    # Analyse the sample page for mitigationMode, userActionsNeeded, and scanStatus
    protect_count = 0
    detect_count = 0
    none_count = 0
    needs_action_count = 0
    scan_failed_count = 0

    for agent in items:
        mode = agent.get("mitigationMode") or ""
        if mode == "protect":
            protect_count = protect_count + 1
        elif mode == "detect":
            detect_count = detect_count + 1
        elif mode == "none":
            none_count = none_count + 1

        actions_needed = agent.get("userActionsNeeded") or []
        if actions_needed:
            needs_action_count = needs_action_count + 1

        scan_status = agent.get("scanStatus") or ""
        if scan_status == "failed":
            scan_failed_count = scan_failed_count + 1

    configured_count = protect_count + detect_count

    has_agents = total_agents > 0
    no_scan_failures = scan_failed_count == 0

    # If mode info is present in the sample, require at least some agents in protect/detect and none in 'none' mode
    mode_data_present = (protect_count + detect_count + none_count) > 0
    if mode_data_present:
        mode_ok = configured_count > 0 and none_count == 0
    else:
        # No mode data surfaced in truncated sample — rely on agent existence and scan health
        mode_ok = True

    is_configured = has_agents and no_scan_failures and mode_ok

    pass_reasons = []
    fail_reasons = []
    recommendations = []
    additional_findings = []

    if is_configured:
        reason = f"{total_agents} agents enrolled in SentinelOne"
        if mode_data_present:
            reason = reason + f"; sampled {sample_count} agents: {protect_count} in 'protect' mode, {detect_count} in 'detect' mode, {none_count} in 'none' mode"
        else:
            reason = reason + f"; sampled {sample_count} agents all reporting healthy scan status (mitigationMode field not present in this page sample)"
        pass_reasons.append(reason)
        if needs_action_count > 0:
            additional_findings.append(f"{needs_action_count} of {sample_count} sampled agents have non-empty userActionsNeeded — review those endpoints in the SentinelOne console.")
    else:
        if not has_agents:
            fail_reasons.append("No enrolled agents found. EPP is not configured.")
            recommendations.append("Deploy the SentinelOne agent to endpoints.")
        if not no_scan_failures:
            fail_reasons.append(f"{scan_failed_count} of {sample_count} sampled agents report scanStatus='failed', indicating EPP health check failures.")
            recommendations.append("Investigate agents with failed scan status in the SentinelOne console and resolve any blocking issues.")
        if mode_data_present and not mode_ok:
            if none_count > 0:
                fail_reasons.append(f"{none_count} of {sample_count} sampled agents have mitigationMode='none', indicating EPP protection is disabled on those agents.")
                recommendations.append("Set mitigationMode to 'protect' or 'detect' on all agents via the SentinelOne policy settings.")
            if configured_count == 0:
                fail_reasons.append("No sampled agents are in 'protect' or 'detect' mode — EPP is not actively configured.")

    return create_response(
        result={
            "isEPPConfigured": is_configured,
            "totalAgents": total_agents,
            "sampleAgentsChecked": sample_count,
            "agentsInProtectMode": protect_count,
            "agentsInDetectMode": detect_count,
            "agentsInNoneMode": none_count,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        additional_findings=additional_findings,
        input_summary={
            "totalAgents": total_agents,
            "sampleAgentsChecked": sample_count,
            "agentsInProtectMode": protect_count,
            "agentsInDetectMode": detect_count,
            "agentsInNoneMode": none_count,
        },
        metadata={
            "transformationId": "isEPPConfigured",
            "vendor": "SentinelOne",
            "category": "epp",
        },
    )
