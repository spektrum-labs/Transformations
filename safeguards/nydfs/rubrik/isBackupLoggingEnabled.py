"""
Transformation: isBackupLoggingEnabled
Vendor: Rubrik  |  Category: nydfs / Backups
Evaluates: Whether backup activity logging is enabled in Rubrik Security Cloud.
Checks that the activitySeriesConnection returns at least one BACKUP type activity record,
confirming backup job events are being recorded and accessible via the audit log.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isBackupLoggingEnabled", "vendor": "Rubrik", "category": "nydfs/Backups"}
        }
    }


def count_by_status(activity_series):
    counts = {}
    for entry in activity_series:
        status = entry.get("status", "UNKNOWN")
        if status not in counts:
            counts[status] = 0
        counts[status] = counts[status] + 1
    return counts


def evaluate(data):
    try:
        activity_series = data.get("data", [])
        if not isinstance(activity_series, list):
            activity_series = []

        total_records = len(activity_series)
        result = total_records > 0

        status_counts = count_by_status(activity_series)

        succeeded = status_counts.get("Success", 0) + status_counts.get("Succeeded", 0) + status_counts.get("SUCCESS", 0)
        failed = status_counts.get("Failure", 0) + status_counts.get("Failed", 0) + status_counts.get("FAILED", 0)
        running = status_counts.get("Running", 0) + status_counts.get("RUNNING", 0) + status_counts.get("InProgress", 0)

        return {
            "isBackupLoggingEnabled": result,
            "totalActivityRecords": total_records,
            "succeededCount": succeeded,
            "failedCount": failed,
            "runningCount": running
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

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        total = eval_result.get("totalActivityRecords", 0)
        succeeded = eval_result.get("succeededCount", 0)
        failed_count = eval_result.get("failedCount", 0)
        running = eval_result.get("runningCount", 0)

        additional_findings.append("Total backup activity records found: " + str(total))
        additional_findings.append("Succeeded: " + str(succeeded) + ", Failed: " + str(failed_count) + ", Running: " + str(running))

        if result_value:
            pass_reasons.append("Backup activity logging is active: " + str(total) + " BACKUP activity series records found in Rubrik Security Cloud.")
            pass_reasons.append("Activity records confirm backup events are being captured in the audit log.")
        else:
            fail_reasons.append("No backup activity series records were returned by the Rubrik API.")
            fail_reasons.append("This may indicate that no backups have run, or that activity logging is not functioning.")
            recommendations.append("Verify that backup jobs are scheduled and running in Rubrik Security Cloud.")
            recommendations.append("Confirm that the service account has sufficient permissions to read activitySeriesConnection data.")
            recommendations.append("Ensure at least one SLA domain is assigned to protected objects so backup events are generated.")

        extra_fields = {
            "totalActivityRecords": total,
            "succeededCount": succeeded,
            "failedCount": failed_count,
            "runningCount": running
        }

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"totalActivityRecords": total}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
