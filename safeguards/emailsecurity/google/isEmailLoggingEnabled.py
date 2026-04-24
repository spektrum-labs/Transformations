"""
Transformation: isEmailLoggingEnabled
Vendor: Google  |  Category: emailsecurity
Evaluates: Verifies that Gmail activity logging is enabled by retrieving Gmail activity
events from the Admin SDK Reports API (applicationName=gmail) and confirming that
activity log data is being captured and accessible.
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
                "transformationId": "isEmailLoggingEnabled",
                "vendor": "Google",
                "category": "emailsecurity"
            }
        }
    }


def get_activity_items(data):
    """
    Extract the list of Gmail activity items from the parsed data.
    Handles two shapes:
      - returnSpec-processed: data is already the items list (a list)
      - Raw API response: data is a dict with an 'items' key
    """
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        # Raw Admin SDK Reports response: { "kind": "...", "items": [...] }
        items = data.get("items", None)
        if isinstance(items, list):
            return items
        # Fallback: check for a nested 'data' key holding the list
        nested = data.get("data", None)
        if isinstance(nested, list):
            return nested
    return []


def evaluate(data):
    """
    Core evaluation logic for isEmailLoggingEnabled.

    Gmail activity logging is considered enabled when the Admin SDK Reports API
    returns at least one activity event for applicationName=gmail.  An empty or
    missing items list means logging is either disabled or no events have been
    captured yet.
    """
    try:
        activity_items = get_activity_items(data)
        total_events = len(activity_items)
        logging_enabled = total_events > 0

        # Collect a sample of event kinds for additional findings
        sample_events = []
        count = 0
        for item in activity_items:
            if count >= 5:
                break
            if isinstance(item, dict):
                event_id = item.get("id", {})
                event_time = ""
                event_app = ""
                if isinstance(event_id, dict):
                    event_time = event_id.get("time", "")
                    event_app = event_id.get("applicationName", "")
                actor = item.get("actor", {})
                actor_email = ""
                if isinstance(actor, dict):
                    actor_email = actor.get("email", "")
                sample_events.append({
                    "time": event_time,
                    "applicationName": event_app,
                    "actorEmail": actor_email
                })
            count = count + 1

        return {
            "isEmailLoggingEnabled": logging_enabled,
            "totalActivityEvents": total_events,
            "sampleEvents": sample_events
        }
    except Exception as e:
        return {"isEmailLoggingEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isEmailLoggingEnabled"
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

        total_events = eval_result.get("totalActivityEvents", 0)
        sample_events = eval_result.get("sampleEvents", [])

        if result_value:
            pass_reasons.append(
                "Gmail activity logging is active - " + str(total_events) +
                " event(s) retrieved from the Admin SDK Reports API (applicationName=gmail)."
            )
            if sample_events:
                for ev in sample_events:
                    additional_findings.append(
                        "Event: actor=" + ev.get("actorEmail", "unknown") +
                        ", time=" + ev.get("time", "unknown")
                    )
        else:
            fail_reasons.append(
                "Gmail activity logging appears disabled or no events are accessible. "
                "The Admin SDK Reports API returned zero activity items for applicationName=gmail."
            )
            if "error" in eval_result:
                fail_reasons.append("Evaluation error: " + eval_result["error"])
            recommendations.append(
                "Ensure Gmail audit logging is enabled in the Google Workspace Admin Console "
                "under Reports > Audit > Gmail. Verify that the service account has the "
                "'https://www.googleapis.com/auth/admin.reports.audit.readonly' OAuth scope."
            )
            recommendations.append(
                "Confirm that at least one Gmail activity event has occurred recently, "
                "as the Reports API only surfaces events after they have been generated."
            )

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "totalActivityEvents": total_events,
                criteriaKey: result_value
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
