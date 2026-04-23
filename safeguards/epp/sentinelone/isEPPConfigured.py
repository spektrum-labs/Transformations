"""
Transformation: isEPPConfigured
Vendor: SentinelOne  |  Category: epp
Evaluates: Verify EPP vendor system is operational and properly configured via health check
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isEPPConfigured", "vendor": "SentinelOne", "category": "epp"}
        }
    }


def evaluate(data):
    try:
        if data is None:
            return {"isEPPConfigured": None, "error": "required fields missing from API response: health check data from /system/status endpoint"}

        health_data = {}
        if isinstance(data, dict):
            method_data = data.get("healthCheck", None)
            if isinstance(method_data, dict):
                val = method_data.get("data", {})
                if isinstance(val, dict):
                    health_data = val
            if not health_data:
                val = data.get("data", {})
                if isinstance(val, dict):
                    health_data = val
            if not health_data:
                health_fields = ["health", "status", "id", "createdAt"]
                found = False
                for field in health_fields:
                    if field in data:
                        found = True
                        break
                if found:
                    health_data = data

        health_str = ""
        status_str = ""
        if isinstance(health_data, dict):
            health_raw = health_data.get("health", "")
            status_raw = health_data.get("status", "")
            health_str = health_raw.lower() if isinstance(health_raw, str) else ""
            status_str = status_raw.lower() if isinstance(status_raw, str) else ""

        error_states = ("error", "down", "critical", "unhealthy", "failed", "degraded")
        if health_str in error_states:
            return {"isEPPConfigured": False, "healthStatus": health_str, "error": "SentinelOne system health check returned error state: " + health_str}
        if status_str in error_states:
            return {"isEPPConfigured": False, "healthStatus": status_str, "error": "SentinelOne system status returned error state: " + status_str}

        reported_status = health_str or status_str or "ok"
        return {"isEPPConfigured": True, "healthStatus": reported_status}
    except Exception as e:
        return {"isEPPConfigured": False, "error": str(e)}


def transform(input):
    criteriaKey = "isEPPConfigured"
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
            pass_reasons.append(criteriaKey + " check passed - SentinelOne system is operational and configured")
            for k, v in extra_fields.items():
                pass_reasons.append(k + ": " + str(v))
        elif result_value is None:
            fail_reasons.append(criteriaKey + " could not be determined - health check data unavailable")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Verify the integration is connected to the correct SentinelOne /system/status endpoint.")
        else:
            fail_reasons.append(criteriaKey + " check failed - SentinelOne system health check indicates a problem")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Investigate the SentinelOne management console for system health issues. Check Settings > System Health.")
        return create_response(
            result={criteriaKey: result_value, **extra_fields}, validation=validation,
            pass_reasons=pass_reasons, fail_reasons=fail_reasons, recommendations=recommendations,
            input_summary={criteriaKey: result_value, **extra_fields})
    except Exception as e:
        return create_response(
            result={criteriaKey: False}, validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)], fail_reasons=["Transformation error: " + str(e)])
