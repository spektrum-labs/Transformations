"""
Transformation: isBackupTested
Vendor: CrashPlan  |  Category: nist-sp-800-53-rev-5-security-and-privacy-controls
Evaluates: Whether backups have been successfully completed and tested, by inspecting the
           GET /api/DeviceBackupReport response for devices that have a recent lastBackupDate
           and a non-zero percentComplete value.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for iteration in range(3):
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
                "category": "nist-sp-800-53-rev-5-security-and-privacy-controls"
            }
        }
    }


def parse_date_string(date_str):
    """
    Parse an ISO-8601-like date string (e.g. '2024-03-15T10:22:00.000Z' or '2024-03-15')
    into a list of integer components [year, month, day] for recency comparison.
    Returns None if parsing fails.
    """
    if not date_str:
        return None
    try:
        parts = date_str.replace("T", "-").replace("Z", "").split("-")
        if len(parts) >= 3:
            year = int(parts[0])
            month = int(parts[1])
            day = int(parts[2])
            return [year, month, day]
    except Exception:
        pass
    return None


def days_since(date_components, now_components):
    """
    Estimate the number of days between date_components and now_components
    ([year, month, day] each). Uses a simple approximation.
    """
    d_year = now_components[0] - date_components[0]
    d_month = now_components[1] - date_components[1]
    d_day = now_components[2] - date_components[2]
    return d_year * 365 + d_month * 30 + d_day


def evaluate(data):
    """
    Inspect the merged deviceBackupReport data.
    Passes when at least one device has a non-null lastBackupDate AND
    a percentComplete > 0, indicating backup has been run and verified.
    Reports total devices, devices with completed backups, and devices with no backup activity.
    """
    try:
        report = data.get("deviceBackupReport", [])
        if not isinstance(report, list):
            report = []

        total_devices = len(report)

        if total_devices == 0:
            return {
                "isBackupTested": False,
                "totalDevices": 0,
                "devicesWithCompletedBackup": 0,
                "devicesWithNoBackup": 0,
                "devicesNeverBacked": 0,
                "staleBackupDevices": 0,
                "backupCompletionScore": 0,
                "error": "No devices found in DeviceBackupReport — backup status cannot be verified"
            }

        now = datetime.utcnow()
        now_components = [now.year, now.month, now.day]

        devices_with_completed = 0
        devices_with_no_backup = 0
        devices_never_backed = 0
        stale_devices = 0
        stale_threshold_days = 30

        for device in report:
            last_backup = device.get("lastBackupDate", None)
            percent = device.get("percentComplete", 0)
            if percent is None:
                percent = 0

            has_backup_date = last_backup is not None and last_backup != ""
            has_completion = percent > 0

            if has_backup_date and has_completion:
                devices_with_completed = devices_with_completed + 1
                date_parts = parse_date_string(last_backup)
                if date_parts is not None:
                    age = days_since(date_parts, now_components)
                    if age > stale_threshold_days:
                        stale_devices = stale_devices + 1
            else:
                devices_with_no_backup = devices_with_no_backup + 1
                if not has_backup_date:
                    devices_never_backed = devices_never_backed + 1

        score = 0
        if total_devices > 0:
            score = int((devices_with_completed * 100) / total_devices)

        is_tested = devices_with_completed > 0

        return {
            "isBackupTested": is_tested,
            "totalDevices": total_devices,
            "devicesWithCompletedBackup": devices_with_completed,
            "devicesWithNoBackup": devices_with_no_backup,
            "devicesNeverBacked": devices_never_backed,
            "staleBackupDevices": stale_devices,
            "backupCompletionScore": score
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
            return create_response(
                result={criteria_key: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        eval_result = evaluate(data)
        result_value = eval_result.get(criteria_key, False)

        extra_fields = {}
        for k in eval_result:
            if k != criteria_key and k != "error":
                extra_fields[k] = eval_result[k]

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        total = eval_result.get("totalDevices", 0)
        completed = eval_result.get("devicesWithCompletedBackup", 0)
        no_backup = eval_result.get("devicesWithNoBackup", 0)
        never_backed = eval_result.get("devicesNeverBacked", 0)
        stale = eval_result.get("staleBackupDevices", 0)
        score = eval_result.get("backupCompletionScore", 0)

        if result_value:
            pass_reasons.append(
                str(completed) + " of " + str(total) +
                " device(s) have a completed backup with non-zero completion percentage"
            )
            pass_reasons.append(
                "Backup completion score: " + str(score) + "%"
            )
            if stale > 0:
                additional_findings.append(
                    str(stale) + " device(s) have a last backup older than 30 days — consider reviewing backup frequency"
                )
        else:
            fail_reasons.append(
                "No devices have a verified completed backup in the DeviceBackupReport"
            )
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append(
                "Ensure CrashPlan backup jobs are actively running on all managed devices"
            )
            recommendations.append(
                "Review devices with percentComplete = 0 or missing lastBackupDate in the CrashPlan console"
            )

        if no_backup > 0:
            additional_findings.append(
                str(no_backup) + " device(s) have no completed backup recorded"
            )
        if never_backed > 0:
            additional_findings.append(
                str(never_backed) + " device(s) have never been backed up (no lastBackupDate)"
            )

        result_dict = {criteria_key: result_value}
        for k in extra_fields:
            result_dict[k] = extra_fields[k]

        input_summary = {criteria_key: result_value}
        for k in extra_fields:
            input_summary[k] = extra_fields[k]

        return create_response(
            result=result_dict,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary=input_summary,
            additional_findings=additional_findings
        )

    except Exception as e:
        return create_response(
            result={criteria_key: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
