"""
Transformation: isBackupLoggingEnabled
Vendor: Sophos  |  Category: Backups
Evaluates: Checks whether backup-related events and activities are being captured
and logged in the Sophos Central SIEM events stream.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isBackupLoggingEnabled", "vendor": "Sophos", "category": "Backups"}
        }
    }


def is_backup_related_event(event):
    name = event.get("name", "").lower()
    category = event.get("category", "").lower()
    event_type = event.get("type", "").lower()
    description = event.get("description", "").lower()
    location = event.get("location", "").lower()
    backup_terms = ["backup", "restore", "recovery", "snapshot", "archive"]
    for term in backup_terms:
        if term in name or term in category or term in event_type or term in description or term in location:
            return True
    return False


def evaluate(data):
    try:
        items = data.get("items", [])
        has_more = data.get("has_more", False)

        if not items:
            return {
                "isBackupLoggingEnabled": False,
                "totalEvents": 0,
                "backupRelatedEvents": 0,
                "hasActiveEventStream": False
            }

        total = len(items)
        backup_events = []
        event_categories = []

        for event in items:
            cat = event.get("category", "")
            if cat and cat not in event_categories:
                event_categories.append(cat)
            if is_backup_related_event(event):
                backup_events.append(event.get("id", "unknown"))

        backup_count = len(backup_events)
        logging_enabled = total > 0

        return {
            "isBackupLoggingEnabled": logging_enabled,
            "totalEvents": total,
            "backupRelatedEvents": backup_count,
            "hasActiveEventStream": logging_enabled,
            "hasMoreEvents": has_more,
            "observedCategories": event_categories
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
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        total = extra_fields.get("totalEvents", 0)
        backup_count = extra_fields.get("backupRelatedEvents", 0)
        categories = extra_fields.get("observedCategories", [])

        if result_value:
            pass_reasons.append("Sophos Central SIEM event stream is active with " + str(total) + " events captured")
            if backup_count > 0:
                pass_reasons.append("Backup-related events detected: " + str(backup_count))
            else:
                additional_findings.append("No explicitly backup-labelled events found, but logging stream is active")
            if categories:
                additional_findings.append("Observed event categories: " + ", ".join(categories))
        else:
            fail_reasons.append("No events found in the Sophos Central SIEM event stream")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Verify Sophos Central SIEM integration is configured and event forwarding is enabled")
            recommendations.append("Check that the API credentials have SIEM read permissions")

        result_dict = {"isBackupLoggingEnabled": result_value}
        for k, v in extra_fields.items():
            result_dict[k] = v

        return create_response(
            result=result_dict,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"totalEvents": total, "backupRelatedEvents": backup_count}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
