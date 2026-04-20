"""
Transformation: isEPPLoggingEnabled
Vendor: Microsoft  |  Category: digital-operational-resilience-act-dora
Evaluates: Checks for endpoint/device-related audit log entries to confirm EPP activity logging is enabled.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isEPPLoggingEnabled", "vendor": "Microsoft", "category": "digital-operational-resilience-act-dora"}
        }
    }


EPP_LOG_KEYWORDS = [
    "device", "intune", "enrollment", "compliance", "defender",
    "endpoint", "mdm", "manageddevice", "antivirus", "malware",
    "compliancepolicy", "configuration"
]


def is_epp_log(log):
    activity = log.get("activityDisplayName", "").lower()
    category = log.get("category", "").lower()
    for kw in EPP_LOG_KEYWORDS:
        if kw in activity or kw in category:
            return True
    return False


def get_logs(data):
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        val = data.get("data", None)
        if isinstance(val, list):
            return val
    return []


def evaluate(data):
    try:
        logs = get_logs(data)
        total_logs = len(logs)
        if total_logs == 0:
            return {"isEPPLoggingEnabled": False, "error": "No audit log entries found", "totalLogs": 0, "eppRelatedLogs": 0}

        epp_logs = []
        epp_activities = []

        for log in logs:
            if is_epp_log(log):
                epp_logs.append(log)
                activity = log.get("activityDisplayName", "")
                if activity and activity not in epp_activities:
                    epp_activities.append(activity)

        is_enabled = len(epp_logs) > 0
        return {
            "isEPPLoggingEnabled": is_enabled,
            "totalLogs": total_logs,
            "eppRelatedLogs": len(epp_logs),
            "detectedActivities": ", ".join(epp_activities)
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
        if validation.get("status") == "failed":
            return create_response(result={criteriaKey: False}, validation=validation, fail_reasons=["Input validation failed"])
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if result_value:
            pass_reasons.append("Endpoint/device-related audit log entries found, confirming EPP activity logging is enabled")
            for k in extra_fields:
                pass_reasons.append(k + ": " + str(extra_fields[k]))
        else:
            fail_reasons.append("No endpoint or device-related audit log entries detected in directory audit logs")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Ensure Microsoft Intune and Defender for Endpoint are configured to send activity events to Microsoft Entra ID audit logs, and that AuditLog.Read.All permission is granted")
        result_dict = {criteriaKey: result_value}
        for k in extra_fields:
            result_dict[k] = extra_fields[k]
        return create_response(
            result=result_dict, validation=validation,
            pass_reasons=pass_reasons, fail_reasons=fail_reasons, recommendations=recommendations,
            input_summary={criteriaKey: result_value})
    except Exception as e:
        return create_response(
            result={criteriaKey: False}, validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)], fail_reasons=["Transformation error: " + str(e)])
