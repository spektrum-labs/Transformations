"""
Transformation: isBackupTested
Vendor: CrashPlan  |  Category: nist-sp-800-53-rev-5-security-and-privacy-controls
Evaluates: Whether backups have been recently completed and verified across enrolled devices.
Uses the DeviceBackupReport resource. A backup is considered tested when
backupCompletePercentage is 100.0 OR lastCompletedBackupDate is within 30 days.
Pass condition: majority of active devices satisfy the tested criteria.
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


def parse_date(date_str):
    if not date_str:
        return None
    try:
        date_part = str(date_str).split("T")[0]
        parts = date_part.split("-")
        if len(parts) == 3:
            year = int(parts[0])
            month = int(parts[1])
            day = int(parts[2])
            return datetime(year, month, day)
        return None
    except Exception:
        return None


def days_since(date_obj):
    if date_obj is None:
        return None
    now = datetime.utcnow()
    delta = now - date_obj
    return delta.days


def evaluate(data):
    try:
        report = data.get("deviceBackupReport", [])
        if not isinstance(report, list):
            report = []

        total = len(report)
        if total == 0:
            return {
                "isBackupTested": False,
                "totalDevices": 0,
                "testedCount": 0,
                "notTestedCount": 0,
                "scoreInPercentage": 0,
                "error": "No device backup report entries found in API response"
            }

        tested_count = 0
        stale_devices = []
        threshold_days = 30

        for device in report:
            pct_raw = device.get("backupCompletePercentage", None)
            last_backup_str = device.get("lastCompletedBackupDate", None)
            pct = None
            if pct_raw is not None:
                try:
                    pct = float(str(pct_raw))
                except Exception:
                    pct = None
            backup_date = parse_date(last_backup_str)
            age_days = days_since(backup_date)
            is_complete = pct is not None and pct >= 100.0
            is_recent = age_days is not None and age_days <= threshold_days
            if is_complete or is_recent:
                tested_count = tested_count + 1
            else:
                device_name = device.get("name", device.get("deviceName", device.get("computerName", "unknown")))
                age_label = str(age_days) + " days ago" if age_days is not None else "never"
                stale_devices.append(str(device_name) + " (last backup: " + age_label + ")")

        score = (tested_count * 100) // total
        is_tested = tested_count > (total // 2)

        result = {
            "isBackupTested": is_tested,
            "totalDevices": total,
            "testedCount": tested_count,
            "notTestedCount": total - tested_count,
            "scoreInPercentage": score,
            "thresholdDays": threshold_days
        }
        if stale_devices:
            result["staleDevices"] = stale_devices[:10]
        return result
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
        total = eval_result.get("totalDevices", 0)
        tested = eval_result.get("testedCount", 0)
        score = eval_result.get("scoreInPercentage", 0)
        threshold = eval_result.get("thresholdDays", 30)
        if result_value:
            pass_reasons.append("The majority of CrashPlan devices have recent or complete backups.")
            pass_reasons.append(
                str(tested) + " of " + str(total) + " devices passed the backup tested check (" + str(score) + "%)."
            )
            pass_reasons.append(
                "Criteria: backupCompletePercentage >= 100 or last backup within " + str(threshold) + " days."
            )
        else:
            fail_reasons.append("The majority of CrashPlan devices do not have recent or complete backups.")
            fail_reasons.append(
                str(tested) + " of " + str(total) + " devices passed the backup tested check (" + str(score) + "%)."
            )
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append(
                "Investigate devices with stale or incomplete backups and ensure backups complete successfully."
            )
            recommendations.append(
                "Review network connectivity and backup destination health for devices with no recent backup."
            )
        if "staleDevices" in eval_result:
            additional_findings.append(
                "Devices with stale or incomplete backup (up to 10): " + "; ".join(eval_result["staleDevices"])
            )
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
            input_summary={"totalDevices": total, "testedCount": tested, "scoreInPercentage": score}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
