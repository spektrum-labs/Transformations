"""
Transformation: isEmailSecurityLoggingEnabled
Vendor: Mimecast  |  Category: emailsecurity
Evaluates: Verifies that email security audit event logging is active by confirming
audit events are being generated and retrievable from the Mimecast audit event stream
(getAuditEvents endpoint).
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
                "transformationId": "isEmailSecurityLoggingEnabled",
                "vendor": "Mimecast",
                "category": "emailsecurity"
            }
        }
    }


def extract_audit_events(data):
    """
    The workflow merges all API method results. getAuditEvents stores its
    records under the key 'getAuditEvents'. Fall back to a top-level 'data'
    list if the method-keyed form is absent.
    """
    if isinstance(data, dict):
        if "getAuditEvents" in data:
            records = data["getAuditEvents"]
            if isinstance(records, list):
                return records
        if "data" in data:
            records = data["data"]
            if isinstance(records, list):
                return records
    if isinstance(data, list):
        return data
    return []


def get_event_categories(events):
    """Return a deduplicated list of category values found across all audit events."""
    seen = {}
    result = []
    for event in events:
        if not isinstance(event, dict):
            continue
        cat = event.get("category", event.get("eventCategory", ""))
        cat_str = str(cat)
        if cat_str and cat_str not in seen:
            seen[cat_str] = True
            result.append(cat_str)
    return result


def get_latest_event_time(events):
    """Return the eventTime string of the most recently timestamped event, or empty string."""
    latest = ""
    for event in events:
        if not isinstance(event, dict):
            continue
        event_time = str(event.get("eventTime", event.get("timestamp", event.get("datetime", ""))))
        if event_time and event_time > latest:
            latest = event_time
    return latest


def evaluate(data):
    """
    Core evaluation logic for isEmailSecurityLoggingEnabled.

    Pass conditions:
      - The getAuditEvents endpoint returned at least one audit event record.
        This confirms the Mimecast audit log stream is active and the integration
        has the required 'Audit | Events | Read' permission.

    A non-empty list of events is the definitive signal that audit event logging
    is functioning. An empty list or missing key is treated as a fail because it
    may indicate logging is disabled, the API scope is insufficient, or no events
    have been generated in the query window.
    """
    events = extract_audit_events(data)

    if not isinstance(events, list):
        return {
            "isEmailSecurityLoggingEnabled": False,
            "totalAuditEvents": 0,
            "reason": "Audit events response was not a list"
        }

    total_events = len(events)

    if total_events == 0:
        return {
            "isEmailSecurityLoggingEnabled": False,
            "totalAuditEvents": 0,
            "reason": "No audit events returned; logging may be disabled or the query window returned no results"
        }

    categories = get_event_categories(events)
    latest_event_time = get_latest_event_time(events)

    return {
        "isEmailSecurityLoggingEnabled": True,
        "totalAuditEvents": total_events,
        "uniqueCategories": len(categories),
        "eventCategories": categories,
        "latestEventTime": latest_event_time
    }


def transform(input):
    criteriaKey = "isEmailSecurityLoggingEnabled"
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

        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "reason" and k != "error"}
        reason = eval_result.get("reason", "")

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        if result_value:
            total_events = eval_result.get("totalAuditEvents", 0)
            unique_categories = eval_result.get("uniqueCategories", 0)
            latest_event_time = eval_result.get("latestEventTime", "")
            pass_reasons.append(
                "Mimecast audit event logging is active: " +
                str(total_events) + " event(s) retrieved."
            )
            if unique_categories:
                pass_reasons.append("Unique event categories observed: " + str(unique_categories))
            if latest_event_time:
                additional_findings.append("Most recent audit event timestamp: " + latest_event_time)
            categories = eval_result.get("eventCategories", [])
            if categories:
                additional_findings.append("Categories present: " + ", ".join([str(c) for c in categories]))
        else:
            fail_reasons.append("Mimecast audit event logging does not appear to be active.")
            if reason:
                fail_reasons.append("Detail: " + reason)
            recommendations.append(
                "Enable audit event logging in the Mimecast Administration Console and "
                "confirm that email security events are being captured in the audit stream."
            )
            recommendations.append(
                "Ensure the API application has the 'Audit | Events | Read' permission "
                "so that audit event data can be retrieved via the API."
            )
            recommendations.append(
                "If logging was recently enabled, allow time for events to populate and "
                "re-evaluate. Alternatively, widen the query date range if the API supports it."
            )

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={criteriaKey: result_value, **extra_fields}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
