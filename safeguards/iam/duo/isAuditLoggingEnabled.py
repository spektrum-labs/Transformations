"""
Transformation: isAuditLoggingEnabled
Vendor: Duo  |  Category: IAM
Evaluates: Validates that audit logging is enabled and capturing both authentication events
(via /admin/v2/logs/authentication) and administrator action events (via /admin/v1/logs/administrator).
Checks that log entries are present and that the stat field returns OK.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isAuditLoggingEnabled", "vendor": "Duo", "category": "IAM"}
        }
    }


def evaluate(data):
    try:
        if not isinstance(data, dict):
            return {"isAuditLoggingEnabled": False, "error": "Unexpected data format"}

        authlogs = data.get("authlogs", [])
        adminlogs = data.get("adminlogs", [])
        stat = data.get("stat", "")

        if not isinstance(authlogs, list):
            authlogs = []
        if not isinstance(adminlogs, list):
            adminlogs = []

        auth_logs_present = len(authlogs) > 0
        admin_logs_present = len(adminlogs) > 0
        stat_ok = str(stat).upper() == "OK"

        is_enabled = auth_logs_present and admin_logs_present and stat_ok

        return {
            "isAuditLoggingEnabled": is_enabled,
            "authLogsPresent": auth_logs_present,
            "adminLogsPresent": admin_logs_present,
            "authLogCount": len(authlogs),
            "adminLogCount": len(adminlogs),
            "statOk": stat_ok,
            "stat": stat
        }
    except Exception as e:
        return {"isAuditLoggingEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isAuditLoggingEnabled"
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
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if result_value:
            pass_reasons.append("Audit logging is enabled for both authentication and administrator events")
            pass_reasons.append("Authentication log entries found: " + str(eval_result.get("authLogCount", 0)))
            pass_reasons.append("Administrator log entries found: " + str(eval_result.get("adminLogCount", 0)))
        else:
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            if not eval_result.get("statOk", False):
                fail_reasons.append("Duo API did not return a successful stat: " + str(eval_result.get("stat", "")))
            if not eval_result.get("authLogsPresent", False):
                fail_reasons.append("No authentication log entries found")
                recommendations.append("Ensure authentication logging is active and generating events in Duo")
            if not eval_result.get("adminLogsPresent", False):
                fail_reasons.append("No administrator log entries found")
                recommendations.append("Ensure administrator action logging is active and generating events in Duo")
        return create_response(
            result=eval_result,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "authLogCount": eval_result.get("authLogCount", 0),
                "adminLogCount": eval_result.get("adminLogCount", 0),
                "statOk": eval_result.get("statOk", False)
            }
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
