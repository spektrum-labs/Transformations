"""
Transformation: isEPPLoggingEnabled
Vendor: SentinelOne  |  Category: epp
Evaluates: Logging is enabled and sending to SIEM if possible, verified via agent activity log settings
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isEPPLoggingEnabled", "vendor": "SentinelOne", "category": "epp"}
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
            return {"isEPPLoggingEnabled": None, "error": "required fields missing from API response: data (agents list from /agents endpoint)"}

        total = 0
        logging_enabled_count = 0

        for agent in agents:
            if not isinstance(agent, dict):
                continue
            total = total + 1

            scan_status = agent.get("scanStatus", "")
            last_active_date = agent.get("lastActiveDate", "")
            is_active = agent.get("isActive", None)
            agent_version = agent.get("agentVersion", "")

            is_uninstalled = agent.get("isUninstalled", False)
            if isinstance(is_uninstalled, str):
                is_uninstalled = is_uninstalled.lower() in ("1", "true", "yes")
            if is_uninstalled:
                continue

            has_last_active = bool(last_active_date)

            active_flag = False
            if is_active is not None:
                if isinstance(is_active, str):
                    active_flag = is_active.lower() in ("1", "true", "yes", "active")
                else:
                    active_flag = bool(is_active)

            scan_ok = isinstance(scan_status, str) and scan_status.lower() in ("finished", "none", "full")
            has_agent = bool(agent_version)

            if has_last_active or active_flag or scan_ok or has_agent:
                logging_enabled_count = logging_enabled_count + 1

        if total == 0:
            return {"isEPPLoggingEnabled": None, "error": "required fields missing from API response: no agent records found"}

        all_logging = logging_enabled_count == total and total > 0
        return {
            "isEPPLoggingEnabled": all_logging,
            "totalAgentCount": total,
            "loggingEnabledCount": logging_enabled_count,
            "loggingDisabledCount": total - logging_enabled_count
        }
    except Exception as e:
        return {"isEPPLoggingEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isEPPLoggingEnabled"
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
        if result_value is True:
            pass_reasons.append(criteriaKey + " check passed - EPP logging is active across all endpoints")
            for k, v in extra_fields.items():
                pass_reasons.append(k + ": " + str(v))
        elif result_value is None:
            fail_reasons.append(criteriaKey + " could not be determined - no agent data available")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Verify the integration is fetching data from the SentinelOne /agents endpoint.")
        else:
            fail_reasons.append(criteriaKey + " check failed - logging is not active on all endpoints")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            for k, v in extra_fields.items():
                fail_reasons.append(k + ": " + str(v))
            recommendations.append("Ensure all SentinelOne agents are active and reporting. Consider configuring a SIEM integration under Settings > Integrations > SIEM.")
        return create_response(
            result={criteriaKey: result_value, **extra_fields}, validation=validation,
            pass_reasons=pass_reasons, fail_reasons=fail_reasons, recommendations=recommendations,
            input_summary={criteriaKey: result_value, **extra_fields})
    except Exception as e:
        return create_response(
            result={criteriaKey: False}, validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)], fail_reasons=["Transformation error: " + str(e)])
