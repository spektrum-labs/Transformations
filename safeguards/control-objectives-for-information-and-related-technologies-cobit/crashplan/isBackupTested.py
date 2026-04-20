"""
Transformation: isBackupTested
Vendor: CrashPlan  |  Category: control-objectives-for-information-and-related-technologies-cobit
Evaluates: Whether backups have been completed and tested successfully by inspecting
           lastCompletedBackup timestamps in the DeviceBackupReport resource.
           A recent non-null lastCompletedBackup (within 30 days) indicates a
           tested and successful backup.
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
                "transformationId": "isBackupTested",
                "vendor": "CrashPlan",
                "category": "control-objectives-for-information-and-related-technologies-cobit"
            }
        }
    }


def parse_date_str(date_str):
    """
    Manually parse an ISO 8601 date string (e.g. '2024-01-15T10:30:00.000Z')
    without using datetime.strptime (not available in RestrictedPython).
    Returns a datetime object or None on failure.
    """
    try:
        clean = date_str.replace("Z", "").replace("z", "")
        if "T" in clean:
            parts = clean.split("T")
            date_part = parts[0]
        else:
            date_part = clean
        date_segments = date_part.split("-")
        year = int(date_segments[0])
        month = int(date_segments[1])
        day = int(date_segments[2])
        return datetime(year, month, day)
    except Exception:
        return None


def days_since(dt):
    """Return the number of days between the given datetime and now."""
    now = datetime.utcnow()
    delta_seconds = (now - dt).total_seconds()
    return int(delta_seconds / 86400)


def evaluate(data):
    """
    Evaluates whether backups have been tested by inspecting lastCompletedBackup
    timestamps from the DeviceBackupReport resource. A device is considered to have
    a tested backup if its lastCompletedBackup is non-null and within the last 30 days.
    Overall isBackupTested passes if at least one report exists and all reports with
    a valid timestamp show a recent (<=30 day) completed backup.
    """
    try:
        reports = data.get("deviceBackupReports", [])
        if not isinstance(reports, list):
            reports = []

        total_reports = len(reports)

        if total_reports == 0:
            return {
                "isBackupTested": False,
                "totalReports": 0,
                "reportsWithRecentBackup": 0,
                "reportsWithNoBackup": 0,
                "reportsWithStaleBackup": 0,
                "backupTestedPercentage": 0,
                "reason": "No device backup reports found in CrashPlan"
            }

        recent_threshold_days = 30
        reports_with_recent = 0
        reports_with_no_backup = 0
        reports_with_stale = 0

        for report in reports:
            last_completed = report.get("lastCompletedBackup", None)
            if last_completed is None or last_completed == "" or last_completed == "null":
                reports_with_no_backup = reports_with_no_backup + 1
            else:
                parsed = parse_date_str(str(last_completed))
                if parsed is None:
                    reports_with_no_backup = reports_with_no_backup + 1
                else:
                    age_days = days_since(parsed)
                    if age_days <= recent_threshold_days:
                        reports_with_recent = reports_with_recent + 1
                    else:
                        reports_with_stale = reports_with_stale + 1

        tested_pct = 0
        if total_reports > 0:
            tested_pct = int((reports_with_recent * 100) / total_reports)

        is_tested = total_reports > 0 and reports_with_recent > 0 and reports_with_stale == 0 and reports_with_no_backup == 0

        return {
            "isBackupTested": is_tested,
            "totalReports": total_reports,
            "reportsWithRecentBackup": reports_with_recent,
            "reportsWithNoBackup": reports_with_no_backup,
            "reportsWithStaleBackup": reports_with_stale,
            "backupTestedPercentage": tested_pct,
            "recentBackupThresholdDays": recent_threshold_days
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

        total = eval_result.get("totalReports", 0)
        recent = eval_result.get("reportsWithRecentBackup", 0)
        no_backup = eval_result.get("reportsWithNoBackup", 0)
        stale = eval_result.get("reportsWithStaleBackup", 0)
        tested_pct = eval_result.get("backupTestedPercentage", 0)
        threshold = eval_result.get("recentBackupThresholdDays", 30)

        if result_value:
            pass_reasons.append(
                "All " + str(total) + " device backup report(s) show a completed backup " +
                "within the last " + str(threshold) + " days (" + str(tested_pct) + "% coverage)"
            )
        else:
            if total == 0:
                fail_reasons.append("No device backup reports found; backup has not been tested")
                recommendations.append(
                    "Ensure CrashPlan backup agents are configured and have completed at least one backup"
                )
            else:
                if no_backup > 0:
                    fail_reasons.append(
                        str(no_backup) + " of " + str(total) +
                        " device(s) have no recorded completed backup"
                    )
                    recommendations.append(
                        "Investigate and resolve backup failures for the " + str(no_backup) +
                        " device(s) with no completed backup on record"
                    )
                if stale > 0:
                    fail_reasons.append(
                        str(stale) + " of " + str(total) +
                        " device(s) have a last completed backup older than " +
                        str(threshold) + " days"
                    )
                    recommendations.append(
                        "Review backup schedules for " + str(stale) +
                        " device(s) with stale backup records and ensure they complete successfully"
                    )
            if "error" in eval_result:
                fail_reasons.append("Evaluation error: " + eval_result["error"])

        if recent > 0 and (no_backup > 0 or stale > 0):
            additional_findings.append(
                str(recent) + " device(s) have recent backups but " +
                str(no_backup + stale) + " device(s) are not fully compliant"
            )

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "totalReports": total,
                "reportsWithRecentBackup": recent,
                "reportsWithNoBackup": no_backup,
                "reportsWithStaleBackup": stale,
                "backupTestedPercentage": tested_pct
            }
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
