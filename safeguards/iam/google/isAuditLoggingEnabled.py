"""
Transformation: isAuditLoggingEnabled
Vendor: Google  |  Category: iam
Evaluates: Verifies that audit logging is enabled and operational within the Google
Workspace organization. Confirms the presence of recent administrative activity entries
returned from the Reports API. A non-empty items array with events confirms audit
logging is active.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isAuditLoggingEnabled", "vendor": "Google", "category": "iam"}
        }
    }


def parse_event_time(time_str):
    """Extract date components from an ISO8601 timestamp string without strptime."""
    if not time_str:
        return None
    try:
        date_part = time_str.split("T")[0]
        parts = date_part.split("-")
        if len(parts) == 3:
            return {"year": int(parts[0]), "month": int(parts[1]), "day": int(parts[2])}
        return None
    except Exception:
        return None


def evaluate(data):
    try:
        items = data.get("items", [])
        total_items = len(items)

        if total_items == 0:
            return {
                "isAuditLoggingEnabled": False,
                "auditEventCount": 0,
                "totalEventsFound": 0,
                "mostRecentEventTime": None,
                "uniqueActors": 0,
                "eventTypesSeen": [],
                "error": "No admin audit activity items found — audit logging may be disabled or no activity exists in the query window"
            }

        total_events = 0
        seen_actors = {}
        seen_event_names = {}
        most_recent_time = None

        for item in items:
            actor = item.get("actor", {})
            actor_email = actor.get("email", "")
            if actor_email:
                seen_actors[actor_email] = True

            events = item.get("events", [])
            for event in events:
                total_events = total_events + 1
                event_name = event.get("name", "")
                if event_name:
                    seen_event_names[event_name] = True

            item_id = item.get("id", {})
            event_time = item_id.get("time", "")
            if event_time:
                if most_recent_time is None:
                    most_recent_time = event_time
                elif event_time > most_recent_time:
                    most_recent_time = event_time

        event_names_list = [k for k in seen_event_names]
        unique_actors = len(seen_actors)

        return {
            "isAuditLoggingEnabled": True,
            "auditEventCount": total_items,
            "totalEventsFound": total_events,
            "mostRecentEventTime": most_recent_time,
            "uniqueActors": unique_actors,
            "eventTypesSeen": event_names_list
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
            return create_response(result={criteriaKey: False}, validation=validation, fail_reasons=["Input validation failed"])
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

        audit_count = eval_result.get("auditEventCount", 0)
        total_events = eval_result.get("totalEventsFound", 0)
        most_recent = eval_result.get("mostRecentEventTime", None)
        unique_actors = eval_result.get("uniqueActors", 0)
        event_types = eval_result.get("eventTypesSeen", [])

        if result_value:
            pass_reasons.append("Admin audit log is active: " + str(audit_count) + " activity record(s) returned by the Reports API")
            pass_reasons.append("Total audit events across all records: " + str(total_events))
            if most_recent:
                pass_reasons.append("Most recent audit event timestamp: " + most_recent)
            additional_findings.append("Unique admin actors observed: " + str(unique_actors))
            if event_types:
                additional_findings.append("Event types seen: " + ", ".join(event_types[:20]))
        else:
            fail_reasons.append("No admin audit activity records were returned by the Google Reports API")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Verify that the Admin SDK Reports API is enabled in the Google Cloud project")
            recommendations.append("Confirm the service account has the admin.reports.audit.readonly OAuth scope authorized via domain-wide delegation")
            recommendations.append("Check that the delegated admin account has Super Admin privileges to access audit log data")

        result_dict = {criteriaKey: result_value}
        for k in extra_fields:
            result_dict[k] = extra_fields[k]

        return create_response(
            result=result_dict,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"auditActivityItems": audit_count, "totalEvents": total_events}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
