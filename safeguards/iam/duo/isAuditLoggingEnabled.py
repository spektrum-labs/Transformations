"""
Transformation: isAuditLoggingEnabled
Vendor: Duo  |  Category: iam
Evaluates: Confirms that audit logging is enabled by verifying administrator action log
events (action, description, timestamp, username) are being recorded and returned
from /admin/v1/logs/administrator.
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


def has_required_fields(log_entry):
    has_action = "action" in log_entry and log_entry["action"] is not None
    has_timestamp = ("timestamp" in log_entry or "isotimestamp" in log_entry) and (
        log_entry.get("timestamp") is not None or log_entry.get("isotimestamp") is not None
    )
    has_username = "username" in log_entry and log_entry["username"] is not None
    return has_action and has_timestamp and has_username


def evaluate(data):
    try:
        log_entries = []

        if isinstance(data, list):
            log_entries = data
        elif isinstance(data, dict):
            for candidate_key in ["response", "logs", "admin_logs", "events"]:
                candidate = data.get(candidate_key)
                if isinstance(candidate, list):
                    log_entries = candidate
                    break
            if not log_entries:
                for k in data:
                    if isinstance(data[k], list):
                        log_entries = data[k]
                        break

        total_log_count = len(log_entries)
        logs_present = total_log_count > 0

        well_formed_count = 0
        for entry in log_entries:
            if isinstance(entry, dict) and has_required_fields(entry):
                well_formed_count = well_formed_count + 1

        audit_logging_enabled = logs_present

        most_recent_timestamp = None
        if logs_present:
            for entry in log_entries:
                if isinstance(entry, dict):
                    ts = entry.get("isotimestamp") or entry.get("timestamp")
                    if ts is not None:
                        most_recent_timestamp = str(ts)
                        break

        return {
            "isAuditLoggingEnabled": audit_logging_enabled,
            "totalLogCount": total_log_count,
            "wellFormedLogCount": well_formed_count,
            "logsPresent": logs_present,
            "mostRecentTimestamp": most_recent_timestamp
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
        additional_findings = []

        total_count = extra_fields.get("totalLogCount", 0)
        well_formed = extra_fields.get("wellFormedLogCount", 0)
        most_recent = extra_fields.get("mostRecentTimestamp")

        if result_value:
            pass_reasons.append("Administrator audit log events are being recorded -- " + str(total_count) + " log entries found")
            if well_formed > 0:
                pass_reasons.append(str(well_formed) + " of " + str(total_count) + " entries contain required fields (action, timestamp, username)")
            if most_recent is not None:
                additional_findings.append("Most recent log timestamp: " + str(most_recent))
        else:
            fail_reasons.append("No administrator audit log entries were returned from /admin/v1/logs/administrator")
            recommendations.append("Verify that the Duo Admin API application has 'Grant read log' permission and that audit logging activity has occurred")
            additional_findings.append("An empty log response may indicate logging is not configured or no admin actions have been taken recently")

        result_dict = {criteriaKey: result_value}
        for k in extra_fields:
            result_dict[k] = extra_fields[k]

        summary_dict = {criteriaKey: result_value}
        for k in extra_fields:
            summary_dict[k] = extra_fields[k]

        return create_response(
            result=result_dict,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary=summary_dict,
            additional_findings=additional_findings
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
