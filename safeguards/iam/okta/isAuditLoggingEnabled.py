"""
Transformation: isAuditLoggingEnabled
Vendor: Okta  |  Category: iam
Evaluates: Queries the Okta System Log API (/api/v1/logs) and verifies that audit log
events are being captured, confirming audit logging is enabled for the organization.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for loop_iter in range(3):
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isAuditLoggingEnabled", "vendor": "Okta", "category": "iam"}
        }
    }


def get_logs_list(data):
    """Extract the list of log events from the data regardless of shape."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ["getSystemLogs", "systemLogs", "logs", "events"]:
            if key in data and isinstance(data[key], list):
                return data[key]
        for key in data:
            val = data[key]
            if isinstance(val, list):
                return val
    return []


def get_event_types(logs):
    """Return a deduplicated list of event type names from the log entries."""
    seen = {}
    for log in logs:
        event_type = ""
        if isinstance(log, dict):
            event_type_obj = log.get("eventType", "")
            if isinstance(event_type_obj, str):
                event_type = event_type_obj
            elif isinstance(event_type_obj, dict):
                event_type = event_type_obj.get("name", "")
        if event_type and event_type not in seen:
            seen[event_type] = True
    return list(seen.keys())


def evaluate(data):
    """Verify audit log events are present, confirming audit logging is enabled."""
    try:
        logs = get_logs_list(data)
        total_events = len(logs)
        is_enabled = total_events > 0
        event_types = get_event_types(logs)
        most_recent_timestamp = ""
        if total_events > 0 and isinstance(logs[0], dict):
            most_recent_timestamp = logs[0].get("published", logs[0].get("created", ""))

        return {
            "isAuditLoggingEnabled": is_enabled,
            "totalEventsReturned": total_events,
            "uniqueEventTypesCount": len(event_types),
            "sampleEventTypes": event_types[:5],
            "mostRecentEventTimestamp": most_recent_timestamp
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
            return create_response(result={criteriaKey: False}, validation=validation,
                                   fail_reasons=["Input validation failed"])
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []
        total = extra_fields.get("totalEventsReturned", 0)
        if result_value:
            pass_reasons.append("Okta audit logging is active: " + str(total) + " log event(s) retrieved from the System Log API.")
            ts = extra_fields.get("mostRecentEventTimestamp", "")
            if ts:
                pass_reasons.append("Most recent event timestamp: " + ts)
            sample = extra_fields.get("sampleEventTypes", [])
            if sample:
                additional_findings.append("Sample event types: " + ", ".join(sample))
        else:
            fail_reasons.append("No audit log events were returned from the Okta System Log API.")
            if "error" in eval_result:
                fail_reasons.append("Error: " + eval_result["error"])
            recommendations.append("Ensure audit logging is enabled in your Okta organization and that the API token has read access to /api/v1/logs.")
        additional_findings.append("Total log events retrieved: " + str(total))
        additional_findings.append("Unique event types observed: " + str(extra_fields.get("uniqueEventTypesCount", 0)))
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={criteriaKey: result_value, "totalEventsReturned": total})
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)])
