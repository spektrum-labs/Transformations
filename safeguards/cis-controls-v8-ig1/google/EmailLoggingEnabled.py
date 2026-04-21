"""
Transformation: EmailLoggingEnabled
Vendor: Google  |  Category: cis-controls-v8-ig1
Evaluates: Queries the Admin Reports API Gmail activity log to confirm that email
security logging is active, producing audit records that can be integrated with
SIEM or monitoring systems.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "EmailLoggingEnabled", "vendor": "Google", "category": "cis-controls-v8-ig1"}
        }
    }


def safe_str(val):
    if val is None:
        return ""
    return str(val)


def evaluate(data):
    """
    Check the Gmail audit log items returned by the Admin Reports API.
    If at least one audit log item exists, logging is considered active.
    Also extracts event type summaries for additional context.
    """
    try:
        items = data.get("items", [])
        if not isinstance(items, list):
            items = []

        total_items = len(items)
        logging_enabled = total_items > 0

        event_types = []
        actor_emails = []
        latest_timestamp = ""

        for item in items:
            if not isinstance(item, dict):
                continue
            actor = item.get("actor", {})
            if isinstance(actor, dict):
                email = actor.get("email", "")
                if email and email not in actor_emails:
                    actor_emails.append(email)
            events = item.get("events", [])
            if isinstance(events, list):
                for event in events:
                    if isinstance(event, dict):
                        event_name = event.get("name", "")
                        if event_name and event_name not in event_types:
                            event_types.append(event_name)
            item_id = item.get("id", {})
            if isinstance(item_id, dict):
                ts = item_id.get("time", "")
                if ts and (not latest_timestamp or ts > latest_timestamp):
                    latest_timestamp = ts

        return {
            "EmailLoggingEnabled": logging_enabled,
            "totalAuditLogItems": total_items,
            "eventTypesObserved": event_types,
            "uniqueActorCount": len(actor_emails),
            "latestLogTimestamp": latest_timestamp,
        }
    except Exception as e:
        return {"EmailLoggingEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "EmailLoggingEnabled"
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

        total = eval_result.get("totalAuditLogItems", 0)

        if result_value:
            pass_reasons.append("Gmail audit logging is active: " + safe_str(total) + " audit log record(s) returned from the Admin Reports API.")
            latest = eval_result.get("latestLogTimestamp", "")
            if latest:
                pass_reasons.append("Most recent audit log entry timestamp: " + latest)
        else:
            fail_reasons.append("No Gmail audit log items were returned by the Admin Reports API, indicating email activity logging may not be active or accessible.")
            recommendations.append("Verify that Gmail audit logging is enabled in the Google Workspace Admin Console under Reports > Audit > Gmail.")
            recommendations.append("Ensure the service account has the https://www.googleapis.com/auth/admin.reports.audit.readonly scope delegated.")
            recommendations.append("If logging was recently enabled, allow time for audit records to accumulate before re-evaluating.")
            if "error" in eval_result:
                fail_reasons.append("Evaluation error: " + eval_result["error"])

        event_types = eval_result.get("eventTypesObserved", [])
        if event_types:
            additional_findings.append("Gmail event types observed in audit logs: " + ", ".join(event_types))

        actor_count = eval_result.get("uniqueActorCount", 0)
        if actor_count > 0:
            additional_findings.append("Unique actors observed in audit logs: " + safe_str(actor_count))

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "totalAuditLogItems": total,
                "eventTypesObserved": event_types,
            }
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
