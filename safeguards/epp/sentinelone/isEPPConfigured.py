"""Transformation: isEPPConfigured — checks EPP protection policy configuration via agent mitigationMode and active status."""

import json
from datetime import datetime


def extract_input(input_data):
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

    if total_items == 0 and len(agents) == 0:
        return create_response(
            result={"isEPPConfigured": False, "totalAgents": 0, "sampledAgents": 0, "configuredAgents": 0, "misconfiguredAgents": 0},
            validation=validation,
            fail_reasons=["No agents found in the SentinelOne fleet. EPP cannot be considered configured with zero enrolled endpoints."],
            recommendations=["Enroll endpoints with the SentinelOne agent to establish EPP coverage."],
            input_summary={"totalAgents": 0, "sampledAgents": 0},
            metadata={"transformationId": "isEPPConfigured", "vendor": "SentinelOne", "category": "epp"},
        )

    sampled = len(agents)
    configured_count = 0
    misconfigured_count = 0
    misconfigured_examples = []

    for agent in agents:
        agent = agent if isinstance(agent, dict) else {}
        mitigation_mode = agent.get("mitigationMode") or ""
        is_active = agent.get("isActive")
        is_decommissioned = agent.get("isDecommissioned") or False
        computer_name = agent.get("computerName") or agent.get("id") or "unknown"

        if mitigation_mode:
            if mitigation_mode in ("protect", "detect"):
                configured_count = configured_count + 1
            else:
                misconfigured_count = misconfigured_count + 1
                if len(misconfigured_examples) < 3:
                    misconfigured_examples.append(
                        computer_name + " (mitigationMode=" + str(mitigation_mode) + ")"
                    )
        else:
            if is_active is not False and not is_decommissioned:
                configured_count = configured_count + 1
            else:
                misconfigured_count = misconfigured_count + 1
                if len(misconfigured_examples) < 3:
                    misconfigured_examples.append(
                        computer_name + " (inactive or decommissioned)"
                    )

    is_configured = total_items > 0 and misconfigured_count == 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_configured:
        pass_reasons.append(
            str(total_items) + " agents are enrolled in SentinelOne. "
            "All " + str(sampled) + " sampled agents show EPP protection configured "
            "(mitigationMode=protect/detect or active non-decommissioned agent state). "
            "EPP health check passes."
        )
    else:
        if total_items == 0:
            fail_reasons.append(
                "No agents enrolled in SentinelOne; EPP health check cannot pass with zero endpoints."
            )
            recommendations.append("Enroll endpoints with the SentinelOne agent.")
        if misconfigured_count > 0:
            example_str = ", ".join(misconfigured_examples) if misconfigured_examples else "none captured"
            fail_reasons.append(
                str(misconfigured_count) + " of " + str(sampled) + " sampled agents have EPP misconfigured "
                "(mitigationMode=none or agent inactive/decommissioned). "
                "Examples: " + example_str + "."
            )
            recommendations.append(
                "Review and update the SentinelOne policy for affected agents to set mitigationMode to 'protect'."
            )

    return create_response(
        result={
            "isEPPConfigured": is_configured,
            "totalAgents": total_items,
            "sampledAgents": sampled,
            "configuredAgents": configured_count,
            "misconfiguredAgents": misconfigured_count,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalAgents": total_items,
            "sampledAgents": sampled,
            "configuredAgents": configured_count,
            "misconfiguredAgents": misconfigured_count,
        },
        metadata={"transformationId": "isEPPConfigured", "vendor": "SentinelOne", "category": "epp"},
    )
