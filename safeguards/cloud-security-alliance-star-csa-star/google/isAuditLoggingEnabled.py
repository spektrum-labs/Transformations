"""
Transformation: isAuditLoggingEnabled
Vendor: Google  |  Category: cloud-security-alliance-star-csa-star
Evaluates: Verifies that Google Workspace admin audit logging is active by confirming
the Admin Reports API returns a non-empty items array of admin activity events.
A populated response confirms audit logging is enabled and functioning for the domain.
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
                "vendor": "Google",
                "category": "cloud-security-alliance-star-csa-star"
            }
        }
    }


def evaluate(data):
    """
    Checks admin audit log items array. A non-empty items list confirms
    that admin audit logging is active and events are being captured.
    Also collects sample event names and actor emails for context.
    """
    try:
        items = data.get("items", [])
        if not isinstance(items, list):
            items = []

        total_events = len(items)
        event_names = []
        actor_emails = []
        most_recent_event_time = ""

        for item in items:
            actor = item.get("actor", {})
            if isinstance(actor, dict):
                email = actor.get("email", "")
                if email and email not in actor_emails:
                    actor_emails.append(email)

            events = item.get("events", [])
            if isinstance(events, list):
                for event in events:
                    name = event.get("name", "")
                    if name and name not in event_names:
                        event_names.append(name)

            timestamp = item.get("id", {}).get("time", "")
            if timestamp and (not most_recent_event_time or timestamp > most_recent_event_time):
                most_recent_event_time = timestamp

        is_enabled = total_events > 0

        return {
            "isAuditLoggingEnabled": is_enabled,
            "totalAuditEvents": total_events,
            "uniqueActorCount": len(actor_emails),
            "sampleEventNames": event_names[:10],
            "mostRecentEventTime": most_recent_event_time
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

        total_events = eval_result.get("totalAuditEvents", 0)
        most_recent = eval_result.get("mostRecentEventTime", "")
        sample_events = eval_result.get("sampleEventNames", [])

        if result_value:
            pass_reasons.append("Admin audit logging is confirmed active — " + str(total_events) + " event(s) returned by Admin Reports API")
            if most_recent:
                pass_reasons.append("Most recent audit event timestamp: " + most_recent)
            for ev in sample_events:
                additional_findings.append("Sample audit event type: " + str(ev))
        else:
            fail_reasons.append("Admin audit logging could not be confirmed — Admin Reports API returned an empty items array")
            fail_reasons.append("No admin activity events were found in the audit log response")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Verify that Google Workspace admin audit logging is enabled in the Admin Console under Reports > Audit")
            recommendations.append("Ensure the OAuth token has the admin.reports.audit.readonly scope with super admin privileges")

        combined_result = {criteriaKey: result_value}
        for k in extra_fields:
            combined_result[k] = extra_fields[k]

        return create_response(
            result=combined_result,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "totalAuditEvents": total_events,
                "mostRecentEventTime": most_recent
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
