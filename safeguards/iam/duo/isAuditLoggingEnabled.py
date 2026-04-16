"""
Transformation: isAuditLoggingEnabled
Vendor: Duo  |  Category: IAM
Evaluates: Verifies that audit logging is enabled by retrieving administrator action logs
from /admin/v2/logs/administrator. Confirms the response contains log events with action,
timestamp, and username fields, indicating an active admin audit trail.
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
    """
    Inspect the 'adminlogs' key returned by getAdminLogs.
    Passes when the list is non-empty, confirming the audit trail is active.
    Also checks for expected fields (action, timestamp, username) in the first entry.
    """
    try:
        adminlogs = data.get("adminlogs", [])
        log_count = len(adminlogs)
        logs_present = log_count > 0

        if not logs_present:
            return {
                "isAuditLoggingEnabled": False,
                "adminLogCount": 0,
                "hasActionField": False,
                "hasTimestampField": False,
                "hasUsernameField": False,
                "logStructureValid": False
            }

        sample = adminlogs[0]
        has_action = "action" in sample
        has_timestamp = "timestamp" in sample
        has_username = "username" in sample
        log_structure_valid = has_action and has_timestamp and has_username

        return {
            "isAuditLoggingEnabled": logs_present,
            "adminLogCount": log_count,
            "hasActionField": has_action,
            "hasTimestampField": has_timestamp,
            "hasUsernameField": has_username,
            "logStructureValid": log_structure_valid
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

        extra_fields = {}
        for k in eval_result:
            if k != criteriaKey and k != "error":
                extra_fields[k] = eval_result[k]

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        if result_value:
            pass_reasons.append("Administrator audit logs are present and accessible")
            pass_reasons.append("Admin log count: " + str(eval_result.get("adminLogCount", 0)))
            if eval_result.get("logStructureValid"):
                pass_reasons.append("Log entries contain expected fields: action, timestamp, and username")
            else:
                additional_findings.append("Log entries were found but may be missing some expected fields (action, timestamp, username)")
                if not eval_result.get("hasActionField"):
                    additional_findings.append("'action' field missing from log entries")
                if not eval_result.get("hasTimestampField"):
                    additional_findings.append("'timestamp' field missing from log entries")
                if not eval_result.get("hasUsernameField"):
                    additional_findings.append("'username' field missing from log entries")
        else:
            if eval_result.get("error"):
                fail_reasons.append(eval_result["error"])
            else:
                fail_reasons.append("No administrator audit log entries were found in the response")
                recommendations.append("Verify that the Admin API integration has 'Grant read log' permission enabled in the Duo Admin Panel")
                recommendations.append("Confirm that administrative actions have been performed recently to generate log entries")
                recommendations.append("Check that the API credentials used have the required log read permissions")

        result_dict = {}
        result_dict[criteriaKey] = result_value
        for k in extra_fields:
            result_dict[k] = extra_fields[k]

        summary_dict = {}
        summary_dict[criteriaKey] = result_value
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
