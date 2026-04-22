"""
Transformation: isEPPEnabledForCriticalSystems
Vendor: Halcyon  |  Category: epp
Evaluates: Checks that Halcyon EPP agents are actively deployed and enabled on systems tagged or
classified as critical, ensuring prioritised ransomware protection for high-value assets.
"""
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isEPPEnabledForCriticalSystems", "vendor": "Halcyon", "category": "epp"}
        }
    }


CRITICAL_TAGS = ["critical", "Critical", "CRITICAL", "high-value", "high_value", "tier1", "tier-1", "Tier1", "Tier 1"]
ACTIVE_STATUSES = ["active", "Active", "ACTIVE", "online", "Online", "ONLINE", "connected", "Connected", "enabled", "Enabled"]


def is_critical_agent(agent):
    tags = agent.get("tags", [])
    if isinstance(tags, list):
        for tag in tags:
            tag_val = tag if isinstance(tag, str) else str(tag)
            tag_lower = tag_val.lower()
            if "critical" in tag_lower or "high-value" in tag_lower or "tier1" in tag_lower or "tier 1" in tag_lower:
                return True
    if isinstance(tags, str):
        tag_lower = tags.lower()
        if "critical" in tag_lower or "high-value" in tag_lower:
            return True
    labels = agent.get("labels", {})
    if isinstance(labels, dict):
        for lk in labels:
            lv = labels[lk]
            combined = (str(lk) + " " + str(lv)).lower()
            if "critical" in combined or "high-value" in combined:
                return True
    criticality = agent.get("criticality", "")
    if isinstance(criticality, str) and criticality.lower() in ["critical", "high"]:
        return True
    group = agent.get("group", "") or agent.get("group_name", "") or agent.get("groupName", "")
    if isinstance(group, str) and ("critical" in group.lower() or "high-value" in group.lower()):
        return True
    return False


def is_agent_active(agent):
    status = agent.get("status", "") or agent.get("agentStatus", "") or agent.get("agent_status", "")
    if isinstance(status, str) and status in ACTIVE_STATUSES:
        return True
    enabled = agent.get("enabled", None)
    if enabled is True:
        return True
    protection = agent.get("protection_state", "") or agent.get("protectionState", "")
    if isinstance(protection, str) and protection.lower() in ["active", "enabled", "protected"]:
        return True
    return False


def evaluate(data):
    try:
        agents_raw = data.get("data", [])
        if not isinstance(agents_raw, list):
            agents_raw = []

        if len(agents_raw) == 0:
            return {
                "isEPPEnabledForCriticalSystems": False,
                "totalAgents": 0,
                "criticalAgentsTotal": 0,
                "criticalAgentsActive": 0,
                "scoreInPercentage": 0,
                "error": "No agent data returned from API"
            }

        critical_agents = [a for a in agents_raw if is_critical_agent(a)]
        total_critical = len(critical_agents)

        if total_critical == 0:
            total = len(agents_raw)
            active_count = len([a for a in agents_raw if is_agent_active(a)])
            score = 0
            if total > 0:
                score = (active_count * 100) / total
            passed = score >= 90
            return {
                "isEPPEnabledForCriticalSystems": passed,
                "totalAgents": total,
                "criticalAgentsTotal": 0,
                "criticalAgentsActive": active_count,
                "scoreInPercentage": score,
                "note": "No agents tagged as critical found; evaluated across all agents"
            }

        active_critical = [a for a in critical_agents if is_agent_active(a)]
        active_critical_count = len(active_critical)
        score = (active_critical_count * 100) / total_critical
        passed = score >= 90

        inactive_hostnames = [
            a.get("hostname", a.get("name", a.get("id", "unknown")))
            for a in critical_agents
            if not is_agent_active(a)
        ]

        result = {
            "isEPPEnabledForCriticalSystems": passed,
            "totalAgents": len(agents_raw),
            "criticalAgentsTotal": total_critical,
            "criticalAgentsActive": active_critical_count,
            "criticalAgentsInactive": total_critical - active_critical_count,
            "scoreInPercentage": score
        }
        if inactive_hostnames:
            result["inactiveCriticalHosts"] = inactive_hostnames
        return result
    except Exception as e:
        return {"isEPPEnabledForCriticalSystems": False, "error": str(e)}


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
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []
        score = eval_result.get("scoreInPercentage", 0)
        total_critical = eval_result.get("criticalAgentsTotal", 0)
        active_critical = eval_result.get("criticalAgentsActive", 0)
        note = eval_result.get("note", "")
        if result_value:
            pass_reasons.append("Halcyon EPP agents are active on critical systems (" + str(active_critical) + "/" + str(total_critical) + " critical agents enabled)")
            pass_reasons.append("Coverage score: " + str(round(score, 1)) + "%")
            if note:
                additional_findings.append(note)
        else:
            fail_reasons.append("EPP coverage on critical systems is insufficient (" + str(active_critical) + "/" + str(total_critical) + " critical agents active, score: " + str(round(score, 1)) + "%)")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            if note:
                additional_findings.append(note)
            inactive_hosts = eval_result.get("inactiveCriticalHosts", [])
            if inactive_hosts:
                additional_findings.append("Inactive critical hosts: " + ", ".join([str(h) for h in inactive_hosts]))
            recommendations.append("Ensure Halcyon EPP agents are installed and active on all systems classified as critical")
            recommendations.append("Review agent tags and group assignments to ensure critical systems are correctly identified")
            recommendations.append("Investigate inactive agents on critical hosts and remediate connectivity or configuration issues")
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"totalAgents": eval_result.get("totalAgents", 0), "criticalAgentsTotal": total_critical, "criticalAgentsActive": active_critical, "scoreInPercentage": score}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
