
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
    """isEPPEnabled (SentinelOne, GET /web/api/v2.1/agents).

    An agent has endpoint protection ENABLED when its mitigationMode is "protect" or "detect"
    (the engine is running; "none" disables it) AND it reports a non-empty activeProtection list.
    True only when at least one agent is returned and every returned agent is enabled; the
    percentage is emitted as eppEnabledPercentage. Enrolment alone (the old totalItems > 0 rule)
    is not evidence: an agent with mitigationMode "none" is enrolled and unprotected.
    Fails closed on an error body, an unreadable agent list and an empty fleet.
    """
    data, validation = extract_input(input)
    if isinstance(data, dict) and (data.get("errors") or data.get("error")):
        reason = "SentinelOne returned an error instead of an agent list"
        return create_response(
            result={"isEPPEnabled": False, "eppEnabledPercentage": 0, "totalAgents": 0, "enabledAgents": 0},
            validation=validation, api_errors=[reason], fail_reasons=[reason],
            metadata={"transformationId": "isEPPEnabled", "vendor": "SentinelOne", "category": "epp"},
        )
    total_items = 0
    if isinstance(data, list):
        agents = data
    elif isinstance(data, dict):
        agents = data.get("data")
        pagination = data.get("pagination") if isinstance(data.get("pagination"), dict) else {}
        total_items = pagination.get("totalItems") or 0
    else:
        agents = None
    if not isinstance(agents, list):
        agents = []
    agents = [a for a in agents if isinstance(a, dict)]
    sampled = len(agents)
    total_items = int(total_items) if total_items else sampled

    enabled = 0
    disabled_names = []
    for agent in agents:
        mode = str(agent.get("mitigationMode") or "").lower()
        active = agent.get("activeProtection")
        has_protection = isinstance(active, list) and len(active) > 0
        if mode in ("protect", "detect") and has_protection:
            enabled = enabled + 1
        else:
            disabled_names.append(str(agent.get("computerName") or agent.get("uuid") or "unknown"))

    pct = (enabled * 100) // sampled if sampled else 0
    is_enabled = sampled > 0 and enabled == sampled
    summary = (
        str(enabled) + " of " + str(sampled) + " returned agents (" + str(pct) + "%) run protection "
        "(mitigationMode protect or detect, activeProtection reported)"
    )
    pass_reasons = []
    fail_reasons = []
    recommendations = []
    findings = []
    if sampled == 0:
        fail_reasons.append("No SentinelOne agents were returned; endpoint protection is not evidenced")
        recommendations.append("Deploy the SentinelOne agent and confirm the siteId setting")
    elif is_enabled:
        pass_reasons.append(summary)
    else:
        fail_reasons.append(summary)
        findings.append("Agents without protection: " + ", ".join(disabled_names[:5]) + ("..." if len(disabled_names) > 5 else ""))
        recommendations.append("Set mitigationMode to protect (or detect) in the agent policy for every agent")
    if total_items > sampled:
        findings.append("Judged on the " + str(sampled) + " agents returned of " + str(total_items) + " enrolled")
    return create_response(
        result={
            "isEPPEnabled": is_enabled,
            "eppEnabledPercentage": pct,
            "totalAgents": total_items,
            "sampledAgents": sampled,
            "enabledAgents": enabled,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        additional_findings=findings,
        input_summary={"totalAgents": total_items, "sampledAgents": sampled, "enabledAgents": enabled},
        metadata={"transformationId": "isEPPEnabled", "vendor": "SentinelOne", "category": "epp"},
    )
