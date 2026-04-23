"""
Transformation: requiredCoveragePercentage
Vendor: SentinelOne  |  Category: epp
Evaluates: Ensure that the EPP agent is deployed on the required percentage of endpoints
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "requiredCoveragePercentage", "vendor": "SentinelOne", "category": "epp"}
        }
    }


def evaluate(data):
    try:
        agents = []
        if isinstance(data, list):
            agents = data
        elif isinstance(data, dict):
            method_data = data.get("getEndpoints", None)
            if isinstance(method_data, dict):
                val = method_data.get("data", [])
                if isinstance(val, list):
                    agents = val
            if not agents:
                val = data.get("data", [])
                if isinstance(val, list):
                    agents = val
                elif isinstance(val, dict):
                    agents = [val]

        if not agents:
            return {"requiredCoveragePercentage": None, "error": "required fields missing from API response: data (agents list from /agents endpoint)"}

        total = 0
        covered = 0
        unprotected_agents = []

        for agent in agents:
            if not isinstance(agent, dict):
                continue
            total = total + 1
            computer_name = agent.get("computerName", agent.get("hostname", "Unknown"))

            is_uninstalled = agent.get("isUninstalled", False)
            if isinstance(is_uninstalled, str):
                is_uninstalled = is_uninstalled.lower() in ("1", "true", "yes")

            if is_uninstalled:
                unprotected_agents.append(computer_name + " (uninstalled)")
                continue

            agent_version = agent.get("agentVersion", "")
            network_status = agent.get("networkStatus", "")
            is_active = agent.get("isActive", None)

            has_agent = bool(agent_version)
            has_network = isinstance(network_status, str) and network_status.lower() in ("connected", "disconnected", "connecting")

            active_flag = False
            if is_active is not None:
                if isinstance(is_active, str):
                    active_flag = is_active.lower() in ("1", "true", "yes", "active")
                else:
                    active_flag = bool(is_active)

            if has_agent or has_network or active_flag:
                covered = covered + 1
            else:
                unprotected_agents.append(computer_name)

        if total == 0:
            return {"requiredCoveragePercentage": None, "error": "required fields missing from API response: no agent records found"}

        percentage = round((covered / total) * 100) if total > 0 else 0
        return {
            "requiredCoveragePercentage": percentage,
            "totalAgentCount": total,
            "coveredAgentCount": covered,
            "uncoveredAgentCount": total - covered
        }
    except Exception as e:
        return {"requiredCoveragePercentage": None, "error": str(e)}


def transform(input):
    criteriaKey = "requiredCoveragePercentage"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, None)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if result_value is None:
            fail_reasons.append(criteriaKey + " could not be determined - no agent data available")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Verify the integration is fetching data from the SentinelOne /agents endpoint.")
        else:
            for k, v in extra_fields.items():
                pass_reasons.append(k + ": " + str(v))
            pass_reasons.append("EPP coverage computed: " + str(result_value) + "%")
            if result_value < 100:
                recommendations.append("Deploy the SentinelOne agent to all managed endpoints to achieve 100% EPP coverage.")
        return create_response(
            result={criteriaKey: result_value, **extra_fields}, validation=validation,
            pass_reasons=pass_reasons, fail_reasons=fail_reasons, recommendations=recommendations,
            input_summary={criteriaKey: result_value, **extra_fields})
    except Exception as e:
        return create_response(
            result={criteriaKey: None}, validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)], fail_reasons=["Transformation error: " + str(e)])
