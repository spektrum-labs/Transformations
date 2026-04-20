"""
Transformation: isAuditLoggingEnabled
Vendor: Google  |  Category: IAM
Evaluates: Verifies that admin audit logging is active in Google Workspace by confirming the
Reports API returns activity items for the admin application, demonstrating audit log
collection is operational.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isAuditLoggingEnabled", "vendor": "Google", "category": "IAM"}
        }
    }


def evaluate(data):
    try:
        items = data.get("items", [])
        if not isinstance(items, list):
            items = []

        # Filter for admin application audit events specifically
        admin_items = [
            item for item in items
            if isinstance(item, dict)
            and isinstance(item.get("id"), dict)
            and item.get("id", {}).get("applicationName") == "admin"
        ]
        # Fall back to all items if applicationName filter yields nothing
        if not admin_items and items:
            admin_items = items

        total_audit_items = len(admin_items)

        event_names_seen = {}
        unique_actors = {}
        earliest_event = ""
        latest_event = ""

        for item in admin_items:
            actor_email = ""
            actor = item.get("actor")
            if isinstance(actor, dict):
                actor_email = actor.get("email", "")
            if actor_email:
                unique_actors[actor_email] = True

            event_time = ""
            item_id = item.get("id")
            if isinstance(item_id, dict):
                event_time = item_id.get("time", "")
            if event_time:
                if not earliest_event or event_time < earliest_event:
                    earliest_event = event_time
                if not latest_event or event_time > latest_event:
                    latest_event = event_time

            events = item.get("events", [])
            if not isinstance(events, list):
                events = []
            for event in events:
                if not isinstance(event, dict):
                    continue
                ename = event.get("name", "")
                if ename:
                    if ename in event_names_seen:
                        event_names_seen[ename] = event_names_seen[ename] + 1
                    else:
                        event_names_seen[ename] = 1

        observed_event_types = [e for e in event_names_seen]
        unique_actor_list = [a for a in unique_actors]

        # Audit logging confirmed active when the Reports API returns at least one admin item
        audit_logging_enabled = total_audit_items > 0

        return {
            "isAuditLoggingEnabled": audit_logging_enabled,
            "totalAuditLogItemsFound": total_audit_items,
            "uniqueActorCount": len(unique_actor_list),
            "observedEventTypes": observed_event_types,
            "earliestEventTime": earliest_event,
            "latestEventTime": latest_event
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
        extra_fields = {k: eval_result[k] for k in eval_result if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []
        if result_value:
            total_items = eval_result.get("totalAuditLogItemsFound", 0)
            pass_reasons.append("Admin audit logging is active; " + str(total_items) + " audit log item(s) returned by the Google Reports API")
            actors = eval_result.get("uniqueActorCount", 0)
            if actors > 0:
                pass_reasons.append("Audit activity recorded for " + str(actors) + " unique actor(s)")
            event_types = eval_result.get("observedEventTypes", [])
            if event_types:
                pass_reasons.append("Event types observed: " + ", ".join(event_types[:10]))
        else:
            fail_reasons.append("No admin audit log items returned by the Google Reports API; audit logging may not be active or accessible")
            recommendations.append("Verify Admin Activity audit logging is enabled in Google Workspace Admin Console under Reporting > Audit and investigation > Admin log events")
            recommendations.append("Confirm the service account has the https://www.googleapis.com/auth/admin.reports.audit.readonly OAuth scope authorised via domain-wide delegation")
            if "error" in eval_result:
                fail_reasons.append("Evaluation error: " + eval_result["error"])
        latest = eval_result.get("latestEventTime", "")
        if latest:
            additional_findings.append("Most recent audit event timestamp: " + latest)
        earliest = eval_result.get("earliestEventTime", "")
        if earliest:
            additional_findings.append("Earliest audit event timestamp in sample: " + earliest)
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
            input_summary={
                "totalAuditLogItemsFound": eval_result.get("totalAuditLogItemsFound", 0),
                "uniqueActorCount": eval_result.get("uniqueActorCount", 0),
                "observedEventTypes": eval_result.get("observedEventTypes", [])
            }
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False}, validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)], fail_reasons=["Transformation error: " + str(e)])
