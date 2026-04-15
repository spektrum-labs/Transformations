"""
Transformation: isAuditLoggingEnabled
Vendor: Duo  |  Category: MFA
Evaluates: Validates that audit logging is enabled in Duo by querying the Admin API
v2 activity log endpoint. A successful response containing at least one log entry
confirms that activity audit logging is active and accessible.
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
                "category": "MFA"
            }
        }
    }


def evaluate(data):
    """
    Inspect the activity log response from /admin/v2/logs/activity.
    data is expected to be a list of log event dicts after returnSpec processing.
    Passes when the list contains at least one event, confirming the endpoint
    is reachable and logging is active.
    Also surfaces the most recent event timestamp and a sample of event types.
    """
    try:
        log_entries = []

        if isinstance(data, list):
            log_entries = data
        elif isinstance(data, dict):
            # Some wrapper shapes keep the list under 'items', 'events', or 'logs'
            for candidate_key in ["items", "events", "logs", "authlogs"]:
                candidate = data.get(candidate_key, [])
                if isinstance(candidate, list) and len(candidate) > 0:
                    log_entries = candidate
                    break
            # Final fallback: if no known key found, treat as empty

        total_entries = len(log_entries)
        logging_active = total_entries > 0

        # Collect a sample of event/action types (up to 5 distinct values)
        action_types = []
        seen_actions = {}
        latest_timestamp = ""

        for entry in log_entries:
            if not isinstance(entry, dict):
                continue

            # Timestamp: Duo activity logs use 'ts' (ISO string) or 'timestamp' (epoch)
            ts = entry.get("ts", entry.get("isotimestamp", entry.get("timestamp", "")))
            if ts and latest_timestamp == "":
                latest_timestamp = str(ts)
            elif ts and str(ts) > latest_timestamp:
                latest_timestamp = str(ts)

            # Action/event type
            action = entry.get("action", entry.get("eventtype", entry.get("type", "")))
            if action and action not in seen_actions and len(action_types) < 5:
                seen_actions[action] = True
                action_types.append(str(action))

        return {
            "isAuditLoggingEnabled": logging_active,
            "totalLogEntriesReturned": total_entries,
            "latestEventTimestamp": latest_timestamp,
            "sampleEventTypes": action_types
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
                result={criteriaKey: False, "totalLogEntriesReturned": 0},
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

        if "error" in eval_result:
            fail_reasons.append("Evaluation error: " + eval_result["error"])
            recommendations.append(
                "Ensure getActivityLogs returns a valid list from the Duo "
                "/admin/v2/logs/activity endpoint"
            )
        else:
            total = eval_result.get("totalLogEntriesReturned", 0)
            latest_ts = eval_result.get("latestEventTimestamp", "")
            sample_types = eval_result.get("sampleEventTypes", [])

            if result_value:
                pass_reasons.append(
                    "Duo activity audit log endpoint returned " + str(total) + " log entr"
                    + ("y" if total == 1 else "ies") + ", confirming audit logging is active"
                )
                if latest_ts:
                    pass_reasons.append("Most recent log event timestamp: " + latest_ts)
                if len(sample_types) > 0:
                    additional_findings.append(
                        "Sample event types observed: " + ", ".join(sample_types)
                    )
            else:
                fail_reasons.append(
                    "The Duo activity log endpoint returned zero log entries. "
                    "Audit logging may be disabled, not configured, or the query "
                    "window returned no events."
                )
                recommendations.append(
                    "Verify that the Duo Admin API application has the 'Grant read log' "
                    "permission enabled and that activity logging is active in the Duo Admin Panel"
                )
                recommendations.append(
                    "Consider widening the mintime query window to capture older events if "
                    "the environment is low-traffic"
                )

        full_result = {criteriaKey: result_value}
        for k in extra_fields:
            full_result[k] = extra_fields[k]

        return create_response(
            result=full_result,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "totalLogEntriesReturned": eval_result.get("totalLogEntriesReturned", 0),
                "latestEventTimestamp": eval_result.get("latestEventTimestamp", "")
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False, "totalLogEntriesReturned": 0},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
