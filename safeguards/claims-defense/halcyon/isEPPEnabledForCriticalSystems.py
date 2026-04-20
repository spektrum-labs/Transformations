"""
Transformation: isEPPEnabledForCriticalSystems
Vendor: Halcyon  |  Category: Claims Defense
Evaluates: Verifies that Halcyon anti-ransomware agents are deployed, active, and in a
protected (not detection-only) state on endpoints tagged or classified as critical within
the tenant. Uses the getAgents endpoint which returns a list of agent objects with status,
group membership, and policy assignment details.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for i in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None,
                    api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isEPPEnabledForCriticalSystems", "vendor": "Halcyon", "category": "Claims Defense"}
        }
    }


def is_critical_agent(agent):
    """
    Determine whether an agent is associated with a critical system.
    Checks group/tag names, hostname patterns, and policy labels for
    common critical indicators. Returns True if the agent is classified critical.
    """
    critical_keywords = ["critical", "server", "dc", "domain controller", "prod", "production", "finance", "hr", "core", "infra", "infrastructure"]

    hostname = str(agent.get("hostname", "") or agent.get("name", "") or agent.get("deviceName", "") or "").lower()
    group_name = str(agent.get("group", "") or agent.get("groupName", "") or "").lower()
    policy_name = str(agent.get("policy", "") or agent.get("policyName", "") or "").lower()

    tags = agent.get("tags", [])
    if tags is None:
        tags = []
    tag_string = ""
    if isinstance(tags, list):
        tag_string = " ".join([str(t).lower() for t in tags])
    elif isinstance(tags, str):
        tag_string = tags.lower()

    combined = hostname + " " + group_name + " " + policy_name + " " + tag_string

    for keyword in critical_keywords:
        if keyword in combined:
            return True
    return False


def is_agent_active_and_protected(agent):
    """
    Returns True if the agent is active and in full-protection (not detection-only) mode.
    """
    status = str(agent.get("status", "") or "").lower().strip()
    mode = str(agent.get("mode", "") or agent.get("protectionMode", "") or agent.get("agentMode", "") or "").lower().strip()
    health = str(agent.get("health", "") or agent.get("healthStatus", "") or "").lower().strip()
    is_active = str(agent.get("isActive", "") or "").lower().strip()
    protection_status = str(agent.get("protectionStatus", "") or "").lower().strip()

    active_indicators = ["active", "online", "connected", "healthy", "protected"]
    inactive_indicators = ["inactive", "offline", "disconnected", "disabled", "error", "degraded", "unprotected"]

    status_active = False
    if status in active_indicators:
        status_active = True
    if health in active_indicators:
        status_active = True
    if is_active in ["true", "1", "yes"]:
        status_active = True
    if protection_status in active_indicators:
        status_active = True

    for ind in inactive_indicators:
        if ind in status or ind in health or ind in protection_status:
            status_active = False
            break

    detection_only_indicators = ["detection", "detect", "audit", "passive", "monitor", "readonly", "read-only"]
    mode_protected = True
    for ind in detection_only_indicators:
        if ind in mode:
            mode_protected = False
            break

    return status_active and mode_protected


def evaluate(data):
    criteriaKey = "isEPPEnabledForCriticalSystems"
    try:
        agents_raw = data.get("agents", [])
        if agents_raw is None:
            agents_raw = []
        if not isinstance(agents_raw, list):
            agents_raw = []

        total_agents = len(agents_raw)

        if total_agents == 0:
            return {
                criteriaKey: False,
                "totalAgents": 0,
                "criticalAgentsTotal": 0,
                "criticalAgentsProtected": 0,
                "criticalAgentsUnprotected": 0,
                "scoreInPercentage": 0,
                "error": "No agents returned from Halcyon API. Cannot evaluate EPP coverage for critical systems."
            }

        critical_agents = [a for a in agents_raw if is_critical_agent(a)]
        critical_total = len(critical_agents)

        if critical_total == 0:
            protected_active = [a for a in agents_raw if is_agent_active_and_protected(a)]
            protected_count = len(protected_active)
            score = 0
            if total_agents > 0:
                score = (protected_count * 100) // total_agents
            result_value = score >= 80
            return {
                criteriaKey: result_value,
                "totalAgents": total_agents,
                "criticalAgentsTotal": 0,
                "criticalAgentsProtected": protected_count,
                "criticalAgentsUnprotected": total_agents - protected_count,
                "scoreInPercentage": score,
                "note": "No agents were explicitly tagged as critical. Evaluated all agents as fallback."
            }

        protected_critical = [a for a in critical_agents if is_agent_active_and_protected(a)]
        protected_count = len(protected_critical)
        unprotected_count = critical_total - protected_count
        score = (protected_count * 100) // critical_total
        result_value = score >= 80

        unprotected_hosts = []
        for a in critical_agents:
            if not is_agent_active_and_protected(a):
                host = str(a.get("hostname", "") or a.get("name", "") or a.get("deviceName", "") or "unknown")
                unprotected_hosts.append(host)

        return {
            criteriaKey: result_value,
            "totalAgents": total_agents,
            "criticalAgentsTotal": critical_total,
            "criticalAgentsProtected": protected_count,
            "criticalAgentsUnprotected": unprotected_count,
            "scoreInPercentage": score,
            "unprotectedCriticalHosts": unprotected_hosts
        }
    except Exception as e:
        return {criteriaKey: False, "error": str(e)}


def transform(input):
    criteriaKey = "isEPPEnabledForCriticalSystems"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(result={criteriaKey: False}, validation=validation, fail_reasons=["Input validation failed"])

        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        total_agents = eval_result.get("totalAgents", 0)
        critical_total = eval_result.get("criticalAgentsTotal", 0)
        protected_count = eval_result.get("criticalAgentsProtected", 0)
        unprotected_count = eval_result.get("criticalAgentsUnprotected", 0)
        score = eval_result.get("scoreInPercentage", 0)
        unprotected_hosts = eval_result.get("unprotectedCriticalHosts", [])
        note = eval_result.get("note", "")

        if note:
            additional_findings.append(note)

        if "error" in eval_result:
            fail_reasons.append(eval_result["error"])
            recommendations.append("Ensure Halcyon agents are enrolled and the API is returning agent inventory.")
        elif result_value:
            pass_reasons.append("Halcyon EPP is enabled and active in full-protection mode on critical systems.")
            pass_reasons.append("Protected critical agents: " + str(protected_count) + " of " + str(critical_total if critical_total > 0 else total_agents) + " (" + str(score) + "%).")
        else:
            fail_reasons.append("One or more critical systems do not have Halcyon EPP enabled in full-protection mode.")
            fail_reasons.append("Coverage score: " + str(score) + "%. Minimum required: 80%.")
            if unprotected_count > 0:
                fail_reasons.append(str(unprotected_count) + " critical agent(s) are inactive, in detection-only mode, or in a degraded state.")
            recommendations.append("Enable full-protection mode on all Halcyon agents deployed on critical systems.")
            recommendations.append("Ensure agents are online and healthy. Review the Halcyon console for degraded or detection-only endpoints.")
            if unprotected_hosts:
                additional_findings.append("Unprotected critical hosts: " + ", ".join(unprotected_hosts[:20]))

        additional_findings.append("Total enrolled agents: " + str(total_agents))
        if critical_total > 0:
            additional_findings.append("Critical agents evaluated: " + str(critical_total))

        result_dict = {criteriaKey: result_value}
        result_dict["totalAgents"] = total_agents
        result_dict["criticalAgentsTotal"] = critical_total
        result_dict["criticalAgentsProtected"] = protected_count
        result_dict["criticalAgentsUnprotected"] = unprotected_count
        result_dict["scoreInPercentage"] = score

        summary_dict = {
            "totalAgents": total_agents,
            "criticalAgentsTotal": critical_total,
            "criticalAgentsProtected": protected_count,
            "scoreInPercentage": score
        }

        return create_response(
            result=result_dict,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary=summary_dict
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
