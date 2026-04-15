"""
Transformation: isAuditLoggingEnabled
Vendor: Duo  |  Category: iam
Evaluates: Validates that administrator audit logging is active by confirming that
           GET /admin/v1/logs/administrator returns a non-empty log array with a stat
           of OK, indicating that admin actions (policy changes, user modifications)
           are being recorded for audit purposes.
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
                "transformationId": "isAuditLoggingEnabled",
                "vendor": "Duo",
                "category": "iam"
            }
        }
    }


def evaluate(data):
    try:
        admin_logs = data.get("adminLogs", None)
        stat = data.get("stat", "")

        if admin_logs is None:
            if isinstance(data, list):
                admin_logs = data
                stat = "OK"
            else:
                admin_logs = []

        log_count = len(admin_logs) if isinstance(admin_logs, list) else 0
        stat_ok = str(stat).upper() == "OK" if stat else True

        findings = []

        if log_count > 0:
            findings.append("Admin log entries found: " + str(log_count))
        else:
            findings.append("No admin log entries returned")

        if stat:
            findings.append("API response stat: " + str(stat))

        most_recent_action = ""
        most_recent_timestamp = ""
        if log_count > 0 and isinstance(admin_logs, list):
            last_entry = admin_logs[0]
            if isinstance(last_entry, dict):
                most_recent_action = str(last_entry.get("action", ""))
                ts = last_entry.get("timestamp", last_entry.get("isotimestamp", ""))
                most_recent_timestamp = str(ts)
                if most_recent_action:
                    findings.append("Most recent logged action: " + most_recent_action)
                if most_recent_timestamp:
                    findings.append("Most recent log timestamp: " + most_recent_timestamp)

        is_enabled = log_count > 0 and stat_ok

        return {
            "isAuditLoggingEnabled": is_enabled,
            "adminLogCount": log_count,
            "apiStatOk": stat_ok,
            "mostRecentAction": most_recent_action,
            "mostRecentTimestamp": most_recent_timestamp,
            "findings": findings
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
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = eval_result.get("findings", [])

        if result_value:
            pass_reasons.append("Administrator audit logging is active")
            pass_reasons.append("Admin log entries found: " + str(eval_result.get("adminLogCount", 0)))
            if eval_result.get("mostRecentAction"):
                pass_reasons.append("Most recent logged action: " + eval_result.get("mostRecentAction", ""))
        else:
            log_count = eval_result.get("adminLogCount", 0)
            stat_ok = eval_result.get("apiStatOk", False)
            if log_count == 0:
                fail_reasons.append("No administrator audit log entries were returned from Duo")
            if not stat_ok:
                fail_reasons.append("Duo API response stat was not OK")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Verify that admin audit logging is enabled in the Duo Admin Panel")
            recommendations.append("Ensure the API integration key has 'Grant read log' permission for administrator logs")
            recommendations.append("Check that administrator actions have occurred within the queried time window")

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "adminLogsPresent": eval_result.get("adminLogCount", 0) > 0,
                "adminLogCount": eval_result.get("adminLogCount", 0),
                criteriaKey: result_value
            },
            additional_findings=additional_findings
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
