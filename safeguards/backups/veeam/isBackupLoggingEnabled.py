"""
Transformation: isBackupLoggingEnabled
Vendor: Veeam  |  Category: Backup
Evaluates: Whether audit and authorization event logging is active in Veeam Backup & Replication
           by confirming that recent authorization event records exist via GET /api/v1/authorization/events.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isBackupLoggingEnabled", "vendor": "Veeam", "category": "Backup"}
        }
    }


def evaluate(data):
    try:
        events = data.get("data", [])
        if not isinstance(events, list):
            events = []
        total_events = len(events)
        is_logging_enabled = total_events > 0
        unique_users = {}
        for event in events:
            username = event.get("userName", event.get("username", ""))
            if username and username not in unique_users:
                unique_users[username] = 1
        unique_user_count = len(unique_users)
        sample_events = []
        count = 0
        for event in events:
            if count >= 3:
                break
            event_time = event.get("time", event.get("timestamp", ""))
            event_action = event.get("action", event.get("type", ""))
            event_user = event.get("userName", event.get("username", ""))
            sample_events.append(event_user + " | " + event_action + " | " + event_time)
            count = count + 1
        return {
            "isBackupLoggingEnabled": is_logging_enabled,
            "totalEventsCaptured": total_events,
            "uniqueUserCount": unique_user_count,
            "sampleEvents": sample_events
        }
    except Exception as e:
        return {"isBackupLoggingEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isBackupLoggingEnabled"
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
        total_events = eval_result.get("totalEventsCaptured", 0)
        unique_users = eval_result.get("uniqueUserCount", 0)
        sample_events = eval_result.get("sampleEvents", [])
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []
        if result_value:
            pass_reasons.append(str(total_events) + " authorization event record(s) found, confirming logging is active")
            pass_reasons.append(str(unique_users) + " unique user(s) recorded in the event log")
            if sample_events:
                additional_findings.append("Sample events (user | action | time): " + "; ".join(sample_events))
        else:
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            else:
                fail_reasons.append("No authorization event records found in Veeam Backup and Replication")
                recommendations.append("Verify that audit logging is enabled and events are being captured by VBR")
                recommendations.append("Check that the integration account has sufficient permissions to read authorization events")
        return create_response(
            result={criteriaKey: result_value, "totalEventsCaptured": total_events, "uniqueUserCount": unique_users},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"totalEventsCaptured": total_events, "uniqueUserCount": unique_users})
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)])
