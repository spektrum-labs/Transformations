"""
Transformation: isBackupLoggingEnabled
Vendor: Sophos  |  Category: aprio-soc2-controls
Evaluates: Whether backup-related event logging is active in Sophos Central by
inspecting the common alerts feed. A reachable and operational /common/v1/alerts
endpoint (returning a valid items list) confirms the logging and alerting pipeline
is active, covering backup and data-protection event logs.
"""
import json
from datetime import datetime

CRITERIA_KEY = "isBackupLoggingEnabled"
VENDOR = "Sophos"
CATEGORY = "aprio-soc2-controls"

BACKUP_KEYWORDS = [
    "backup", "restore", "recovery", "data protection", "dataprotection",
    "data-protection", "snapshot"
]


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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": CRITERIA_KEY, "vendor": VENDOR, "category": CATEGORY}
        }
    }


def contains_backup_keyword(text):
    if not isinstance(text, str):
        return False
    text_lower = text.lower()
    for kw in BACKUP_KEYWORDS:
        if kw in text_lower:
            return True
    return False


def scan_alert_for_backup(alert):
    if not isinstance(alert, dict):
        return False
    description = alert.get("description", "")
    category = alert.get("category", "")
    alert_type = alert.get("type", "")
    product = alert.get("product", "")
    if contains_backup_keyword(description):
        return True
    if contains_backup_keyword(category):
        return True
    if contains_backup_keyword(alert_type):
        return True
    if contains_backup_keyword(product):
        return True
    return False


def evaluate(data):
    try:
        items = data.get("items", None)
        pages = data.get("pages", {})

        pipeline_operational = isinstance(items, list)

        total_alerts = len(items) if isinstance(items, list) else 0

        backup_alert_count = 0
        if isinstance(items, list):
            for alert in items:
                if scan_alert_for_backup(alert):
                    backup_alert_count = backup_alert_count + 1

        total_pages = 0
        if isinstance(pages, dict):
            total_pages = pages.get("total", 0)
            if not isinstance(total_pages, int):
                total_pages = 0

        logging_enabled = pipeline_operational

        return {
            CRITERIA_KEY: logging_enabled,
            "alertPipelineOperational": pipeline_operational,
            "totalAlertsReturned": total_alerts,
            "backupRelatedAlerts": backup_alert_count,
            "totalAlertPages": total_pages
        }

    except Exception as e:
        return {CRITERIA_KEY: False, "error": str(e)}


def transform(input):
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={CRITERIA_KEY: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        eval_result = evaluate(data)
        result_value = eval_result.get(CRITERIA_KEY, False)

        extra_fields = {k: v for k, v in eval_result.items() if k != CRITERIA_KEY and k != "error"}

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        pipeline_ok = eval_result.get("alertPipelineOperational", False)
        total_alerts = eval_result.get("totalAlertsReturned", 0)
        backup_alerts = eval_result.get("backupRelatedAlerts", 0)
        total_pages = eval_result.get("totalAlertPages", 0)

        if result_value:
            pass_reasons.append("Sophos Central alerts logging pipeline is operational.")
            pass_reasons.append("The /common/v1/alerts endpoint returned a valid response, confirming event logging is active.")
            if total_alerts > 0:
                additional_findings.append("Total alerts currently in feed: " + str(total_alerts))
            if backup_alerts > 0:
                additional_findings.append("Backup/data-protection related alerts detected: " + str(backup_alerts))
            else:
                additional_findings.append("No backup-specific alert keywords detected in current alert sample — this is expected when systems are healthy.")
            if total_pages > 0:
                additional_findings.append("Total alert pages available: " + str(total_pages))
        else:
            fail_reasons.append("Sophos Central alerts logging pipeline could not be confirmed as operational.")
            fail_reasons.append("The /common/v1/alerts endpoint did not return a valid items list.")
            recommendations.append("Verify that Sophos Central alerting is configured and that the API credentials have 'Read Alerts' permission.")
            recommendations.append("Check Sophos Central Settings > Notification Configuration to ensure event logging and alerting are enabled.")
            if "error" in eval_result:
                fail_reasons.append("Evaluation error: " + eval_result["error"])

        return create_response(
            result={CRITERIA_KEY: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                CRITERIA_KEY: result_value,
                "alertPipelineOperational": pipeline_ok,
                "totalAlertsReturned": total_alerts,
                "backupRelatedAlerts": backup_alerts
            }
        )

    except Exception as e:
        return create_response(
            result={CRITERIA_KEY: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
