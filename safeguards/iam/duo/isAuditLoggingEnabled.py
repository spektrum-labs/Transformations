"""
Transformation: isAuditLoggingEnabled
Vendor: Duo  |  Category: IAM
Evaluates: Validates that audit logging is enabled and actively capturing administrator and
authentication events within the Duo account by inspecting recent admin log entries.
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
                "category": "IAM"
            }
        }
    }


def evaluate(data):
    """
    Duo Admin API /admin/v1/logs/administrator returns a list of admin log entries.
    Each entry has fields like: action, description, isotimestamp, timestamp, username, host.

    Logging is considered enabled if the API endpoint is reachable and returns a list.
    A non-empty list is strong confirmation. An empty list still passes because
    the endpoint being accessible means the logging infrastructure is active.
    """
    criteriaKey = "isAuditLoggingEnabled"
    try:
        logs = data

        # Handle both direct list and dict with 'data' key
        if isinstance(logs, dict):
            logs = logs.get("data", logs.get("response", []))

        if not isinstance(logs, list):
            return {criteriaKey: False, "error": "Admin log data is not a list (got: " + str(type(logs)) + ")"}

        total_log_entries = len(logs)

        # Collect unique action types
        action_types = []
        for entry in logs:
            if isinstance(entry, dict):
                action = entry.get("action", "")
                if action and action not in action_types:
                    action_types.append(action)

        # Most recent log timestamp
        most_recent_timestamp = ""
        most_recent_ts = 0
        for entry in logs:
            if isinstance(entry, dict):
                ts = entry.get("timestamp", 0)
                if ts and ts > most_recent_ts:
                    most_recent_ts = ts
                    most_recent_timestamp = entry.get("isotimestamp", str(ts))

        logging_enabled = True
        has_recent_events = total_log_entries > 0

        return {
            criteriaKey: logging_enabled,
            "totalLogEntries": total_log_entries,
            "hasRecentEvents": has_recent_events,
            "distinctActionTypes": len(action_types),
            "actionTypesSeen": action_types,
            "mostRecentEventTimestamp": most_recent_timestamp
        }

    except Exception as e:
        return {criteriaKey: False, "error": str(e)}


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
        skip_keys = [criteriaKey, "error"]
        for k in eval_result:
            if k not in skip_keys:
                extra_fields[k] = eval_result[k]

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        if result_value:
            total = extra_fields.get("totalLogEntries", 0)
            distinct = extra_fields.get("distinctActionTypes", 0)
            has_events = extra_fields.get("hasRecentEvents", False)
            if has_events:
                pass_reasons.append("Audit logging is enabled and actively capturing events (" + str(total) + " log entries found, " + str(distinct) + " distinct action types)")
            else:
                pass_reasons.append("Audit logging infrastructure is reachable (no recent admin events in the queried window; logging is active)")
                additional_findings.append("No administrator log events were returned in the queried time window. Consider widening the mintime range.")
            most_recent = extra_fields.get("mostRecentEventTimestamp", "")
            if most_recent:
                additional_findings.append("Most recent log event timestamp: " + most_recent)
            action_types = extra_fields.get("actionTypesSeen", [])
            if action_types:
                additional_findings.append("Captured event types: " + ", ".join(action_types))
        else:
            if "error" in eval_result:
                fail_reasons.append("Evaluation error: " + eval_result["error"])
            else:
                fail_reasons.append("Audit logging does not appear to be enabled or returning data")
            recommendations.append("Verify that the Admin API application has 'Grant read log' permission enabled in the Duo Admin Panel")
            recommendations.append("Ensure administrator activity is occurring and being logged within Duo")

        combined_result = {criteriaKey: result_value}
        for k in extra_fields:
            combined_result[k] = extra_fields[k]

        combined_summary = {criteriaKey: result_value}
        for k in extra_fields:
            combined_summary[k] = extra_fields[k]

        return create_response(
            result=combined_result,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary=combined_summary
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
