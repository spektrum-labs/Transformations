"""
Transformation: isBackupTested
Vendor: Sophos  |  Category: Backups
Evaluates: Checks the Sophos Central alerts feed for evidence of recent backup
test completion events by examining backup-related alert types and their
resolution status.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isBackupTested", "vendor": "Sophos", "category": "Backups"}
        }
    }


def is_backup_alert(alert):
    category = alert.get("category", "").lower()
    description = alert.get("description", "").lower()
    alert_type = alert.get("type", "").lower()
    product = alert.get("product", "").lower()
    backup_terms = ["backup", "restore", "recovery", "snapshot"]
    for term in backup_terms:
        if term in category or term in description or term in alert_type or term in product:
            return True
    return False


def alert_is_resolved(alert):
    allowed_actions = alert.get("allowedActions", [])
    if not allowed_actions:
        return True
    actions_lower = [a.lower() for a in allowed_actions]
    if "acknowledge" in actions_lower or "resolved" in actions_lower or "clear" in actions_lower:
        return True
    return False


def evaluate(data):
    try:
        items = data.get("items", [])
        if not items:
            return {
                "isBackupTested": False,
                "totalAlerts": 0,
                "backupRelatedAlerts": 0,
                "resolvedBackupAlerts": 0
            }

        total = len(items)
        backup_alert_ids = []
        resolved_backup_ids = []
        backup_descriptions = []

        for alert in items:
            if is_backup_alert(alert):
                alert_id = alert.get("id", "unknown")
                backup_alert_ids.append(alert_id)
                desc = alert.get("description", "")
                if desc and desc not in backup_descriptions:
                    backup_descriptions.append(desc)
                if alert_is_resolved(alert):
                    resolved_backup_ids.append(alert_id)

        backup_count = len(backup_alert_ids)
        resolved_count = len(resolved_backup_ids)
        result = resolved_count > 0

        return {
            "isBackupTested": result,
            "totalAlerts": total,
            "backupRelatedAlerts": backup_count,
            "resolvedBackupAlerts": resolved_count,
            "backupAlertDescriptions": backup_descriptions
        }
    except Exception as e:
        return {"isBackupTested": False, "error": str(e)}


def transform(input):
    criteriaKey = "isBackupTested"
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

        backup_count = extra_fields.get("backupRelatedAlerts", 0)
        resolved_count = extra_fields.get("resolvedBackupAlerts", 0)
        total = extra_fields.get("totalAlerts", 0)
        descriptions = extra_fields.get("backupAlertDescriptions", [])

        if result_value:
            pass_reasons.append("Backup test evidence found: " + str(resolved_count) + " resolved backup-related alerts")
            pass_reasons.append("Total backup-related alerts in feed: " + str(backup_count))
            for desc in descriptions:
                additional_findings.append("Alert: " + desc)
        else:
            fail_reasons.append("No resolved backup test completion alerts found in Sophos Central alerts feed")
            fail_reasons.append("Total alerts scanned: " + str(total) + ", backup-related: " + str(backup_count))
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Conduct and document regular backup restore tests within Sophos Central")
            recommendations.append("Ensure backup test events are visible in the Sophos Central alerts and event log")

        result_dict = {"isBackupTested": result_value}
        for k, v in extra_fields.items():
            result_dict[k] = v

        return create_response(
            result=result_dict,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"totalAlerts": total, "backupRelatedAlerts": backup_count, "resolvedBackupAlerts": resolved_count}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
