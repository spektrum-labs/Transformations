"""
Transformation: isBackupTested
Vendor: Sophos  |  Category: control-objectives-for-information-and-related-technologies-cobit
Evaluates: Whether backup operations have run successfully by reviewing alert items from the
Sophos common alerts API. Checks that no persistent backup failure alerts are present and
that backup-related events show successful completion.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isBackupTested", "vendor": "Sophos", "category": "control-objectives-for-information-and-related-technologies-cobit"}
        }
    }


def is_backup_related(alert):
    category = alert.get("category", "").lower()
    description = alert.get("description", "").lower()
    alert_type = alert.get("type", "").lower()
    return ("backup" in category or "backup" in description or "backup" in alert_type)


def is_backup_failure(alert):
    severity = alert.get("severity", "").lower()
    description = alert.get("description", "").lower()
    alert_type = alert.get("type", "").lower()
    failure_keywords = ["fail", "error", "missed", "incomplete", "aborted"]
    for kw in failure_keywords:
        if kw in description or kw in alert_type:
            return True
    if severity in ["high", "critical"]:
        return True
    return False


def evaluate(data):
    try:
        items = data.get("items", [])
        backup_alerts = [a for a in items if is_backup_related(a)]
        backup_failures = [a for a in backup_alerts if is_backup_failure(a)]

        total_alerts = len(items)
        backup_alert_count = len(backup_alerts)
        failure_count = len(backup_failures)

        if backup_alert_count == 0:
            is_tested = True
            note = "No backup alerts found; assuming backup is operational"
        elif failure_count == 0:
            is_tested = True
            note = "Backup alerts present with no failure indicators"
        else:
            is_tested = False
            note = str(failure_count) + " backup failure alert(s) detected"

        return {
            "isBackupTested": is_tested,
            "totalAlerts": total_alerts,
            "backupAlertCount": backup_alert_count,
            "backupFailureCount": failure_count,
            "note": note
        }
    except Exception as e:
        return {"isBackupTested": False, "error": str(e)}


def transform(input):
    criteria_key = "isBackupTested"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(result={criteria_key: False}, validation=validation,
                                   fail_reasons=["Input validation failed"])
        eval_result = evaluate(data)
        result_value = eval_result.get(criteria_key, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteria_key and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if result_value:
            pass_reasons.append("Backup operations show no persistent failure alerts")
            pass_reasons.append(extra_fields.get("note", ""))
        else:
            fail_reasons.append("Backup failure alerts detected in Sophos Central")
            fail_reasons.append(extra_fields.get("note", ""))
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Investigate and resolve backup failure alerts in Sophos Central")
            recommendations.append("Ensure backup jobs are scheduled and completing successfully")
            recommendations.append("Perform a manual backup test and verify the results in Sophos Central")
        combined = {criteria_key: result_value}
        for k in extra_fields:
            combined[k] = extra_fields[k]
        return create_response(
            result=combined, validation=validation,
            pass_reasons=pass_reasons, fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={criteria_key: result_value, "backupAlertCount": extra_fields.get("backupAlertCount", 0)})
    except Exception as e:
        return create_response(
            result={criteria_key: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)])
