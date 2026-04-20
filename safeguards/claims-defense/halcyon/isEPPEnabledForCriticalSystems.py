"""
Transformation: isEPPEnabledForCriticalSystems
Vendor: Halcyon  |  Category: claims-defense
Evaluates: Checks that Halcyon EPP agents are deployed and active specifically on endpoints
designated as critical systems (e.g. servers, domain controllers, high-value assets). Filters
the /v1/agents response by device type, isCritical flag, group labels, and tags to verify
EPP coverage on critical infrastructure.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for loop_idx in range(3):
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
            "dataCollection": {
                "status": "error" if (api_errors or []) else "success",
                "errors": api_errors or []
            },
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", [])
            },
            "transformation": {
                "status": "error" if (transformation_errors or []) else "success",
                "errors": transformation_errors or [],
                "inputSummary": input_summary or {}
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or []
            },
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "isEPPEnabledForCriticalSystems",
                "vendor": "Halcyon",
                "category": "claims-defense"
            }
        }
    }


def agent_is_critical(agent):
    critical_device_types = ["server", "dc", "domain_controller", "domain controller", "domaincontroller"]
    critical_tag_keywords = ["critical", "server", "production", "prod", "domain_controller", "dc"]
    critical_group_keywords = ["server", "critical", "dc", "domain controller", "production", "prod"]

    if agent.get("isCritical") is True or agent.get("is_critical") is True:
        return True

    device_type_raw = agent.get("deviceType", agent.get("device_type", agent.get("type", "")))
    if device_type_raw:
        device_type_lower = str(device_type_raw).lower()
        for cdt in critical_device_types:
            if cdt in device_type_lower:
                return True

    tags = agent.get("tags", agent.get("labels", []))
    if isinstance(tags, list):
        for tag in tags:
            tag_lower = str(tag).lower()
            for keyword in critical_tag_keywords:
                if keyword in tag_lower:
                    return True

    group_raw = agent.get("groupName", agent.get("group", agent.get("group_name", "")))
    if group_raw:
        group_lower = str(group_raw).lower()
        for keyword in critical_group_keywords:
            if keyword in group_lower:
                return True

    return False


def agent_is_active(agent):
    active_states = ["active", "healthy", "online", "protected", "running", "enabled"]

    status_raw = agent.get("status", agent.get("protectionStatus", agent.get("state", agent.get("protectionState", ""))))
    if status_raw:
        status_lower = str(status_raw).lower()
        for state in active_states:
            if state in status_lower:
                return True

    if agent.get("protectionEnabled") is True:
        return True
    if agent.get("isActive") is True:
        return True

    return False


def evaluate(data):
    try:
        agents = data.get("data", [])
        if not isinstance(agents, list):
            agents = []

        total_agents = len(agents)

        if total_agents == 0:
            return {
                "isEPPEnabledForCriticalSystems": False,
                "totalAgents": 0,
                "criticalAgentsFound": 0,
                "criticalAgentsActive": 0,
                "criticalAgentsInactive": 0,
                "coveragePercentage": 0,
                "evaluationNote": "No agents found in response"
            }

        critical_agents = []
        for agent in agents:
            if agent_is_critical(agent):
                critical_agents.append(agent)

        critical_count = len(critical_agents)

        if critical_count == 0:
            return {
                "isEPPEnabledForCriticalSystems": False,
                "totalAgents": total_agents,
                "criticalAgentsFound": 0,
                "criticalAgentsActive": 0,
                "criticalAgentsInactive": 0,
                "coveragePercentage": 0,
                "evaluationNote": "No critical systems identified in agent inventory"
            }

        active_critical = []
        inactive_critical = []
        for agent in critical_agents:
            if agent_is_active(agent):
                active_critical.append(agent)
            else:
                inactive_critical.append(agent)

        active_count = len(active_critical)
        inactive_count = len(inactive_critical)
        coverage = (active_count * 100) // critical_count

        inactive_hostnames = []
        for agent in inactive_critical:
            hostname = agent.get("hostname", agent.get("name", agent.get("deviceName", "unknown")))
            inactive_hostnames.append(str(hostname))

        return {
            "isEPPEnabledForCriticalSystems": inactive_count == 0,
            "totalAgents": total_agents,
            "criticalAgentsFound": critical_count,
            "criticalAgentsActive": active_count,
            "criticalAgentsInactive": inactive_count,
            "coveragePercentage": coverage,
            "inactiveHostnames": inactive_hostnames
        }

    except Exception as e:
        return {"isEPPEnabledForCriticalSystems": False, "evaluationNote": str(e)}


def transform(input):
    criteriaKey = "isEPPEnabledForCriticalSystems"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)

        extra_fields = {}
        for k in eval_result:
            if k != criteriaKey and k != "evaluationNote":
                extra_fields[k] = eval_result[k]

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        if result_value:
            pass_reasons.append("All identified critical systems have active Halcyon EPP protection.")
            pass_reasons.append(
                "Critical agents active: " + str(eval_result.get("criticalAgentsActive", 0)) +
                " of " + str(eval_result.get("criticalAgentsFound", 0)) + " identified critical agents."
            )
            pass_reasons.append("EPP coverage on critical systems: " + str(eval_result.get("coveragePercentage", 0)) + "%")
        else:
            note = eval_result.get("evaluationNote", "")
            if note:
                fail_reasons.append(note)
            else:
                fail_reasons.append("One or more critical systems do not have active Halcyon EPP protection.")
                fail_reasons.append(
                    "Inactive critical agents: " + str(eval_result.get("criticalAgentsInactive", 0)) +
                    " of " + str(eval_result.get("criticalAgentsFound", 0)) + " identified."
                )
                inactive_hosts = eval_result.get("inactiveHostnames", [])
                if inactive_hosts:
                    additional_findings.append("Inactive critical hosts: " + ", ".join(inactive_hosts))
            recommendations.append(
                "Ensure all servers and critical endpoints have an active Halcyon EPP agent installed and reporting a healthy status."
            )
            recommendations.append(
                "Classify critical systems in Halcyon using device type (server/dc), group labels, or the isCritical flag so they are correctly identified during evaluation."
            )

        final_result = {criteriaKey: result_value}
        for k in extra_fields:
            final_result[k] = extra_fields[k]

        input_summary = {
            "totalAgents": eval_result.get("totalAgents", 0),
            "criticalAgentsFound": eval_result.get("criticalAgentsFound", 0),
            "criticalAgentsActive": eval_result.get("criticalAgentsActive", 0)
        }

        return create_response(
            result=final_result,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary=input_summary,
            additional_findings=additional_findings
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
