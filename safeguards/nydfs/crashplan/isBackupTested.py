"""
Transformation: isBackupTested
Vendor: CrashPlan  |  Category: nydfs
Evaluates: Whether backups have been successfully completed (tested) within the last 90 days.
Inspects lastCompletedBackup in each computer's backupUsage array. Passes if at least one
device has a completed backup within the 90-day window, validating recoverability.
"""
import json
from datetime import datetime, timedelta


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for i in range(3):
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
                "category": "nydfs"
            }
        }
    }


def parse_date_str(date_str):
    if not date_str:
        return None
    try:
        date_part = date_str.split("T")[0]
        parts = date_part.split("-")
        if len(parts) < 3:
            return None
        year = int(parts[0])
        month = int(parts[1])
        day = int(parts[2])
        return datetime(year, month, day)
    except Exception:
        return None


def evaluate(data):
    try:
        computers = data.get("computers", [])
        total_count = len(computers)
        if total_count == 0:
            return {
                "isBackupTested": False,
                "totalDevices": 0,
                "devicesWithRecentCompletedBackup": 0,
                "devicesWithNoCompletedBackup": 0,
                "testWindowDays": 90,
                "error": "No active computers found — cannot evaluate backup completion status"
            }
        cutoff_date = datetime.utcnow() - timedelta(days=90)
        devices_with_recent = 0
        devices_without = 0
        most_recent_date = None
        most_recent_str = ""
        for computer in computers:
            backup_usage = computer.get("backupUsage", [])
            device_has_recent = False
            for entry in backup_usage:
                completed_str = entry.get("lastCompletedBackup", entry.get("lastCompletedBackupMs", None))
                if not completed_str:
                    continue
                if isinstance(completed_str, int) or isinstance(completed_str, float):
                    completed_dt = datetime(1970, 1, 1) + timedelta(milliseconds=int(completed_str))
                else:
                    completed_dt = parse_date_str(str(completed_str))
                if completed_dt is None:
                    continue
                if completed_dt >= cutoff_date:
                    device_has_recent = True
                if most_recent_date is None or completed_dt > most_recent_date:
                    most_recent_date = completed_dt
                    most_recent_str = str(completed_str)
            if device_has_recent:
                devices_with_recent = devices_with_recent + 1
            else:
                devices_without = devices_without + 1
        is_tested = devices_with_recent > 0
        return {
            "isBackupTested": is_tested,
            "totalDevices": total_count,
            "devicesWithRecentCompletedBackup": devices_with_recent,
            "devicesWithNoCompletedBackup": devices_without,
            "mostRecentCompletedBackup": most_recent_str,
            "testWindowDays": 90
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
        extra_fields = {}
        for k in eval_result:
            if k != criteriaKey and k != "error":
                extra_fields[k] = eval_result[k]
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []
        recent_str = str(eval_result.get("devicesWithRecentCompletedBackup", 0))
        total_str = str(eval_result.get("totalDevices", 0))
        window_str = str(eval_result.get("testWindowDays", 90))
        most_recent = eval_result.get("mostRecentCompletedBackup", "")
        if result_value:
            pass_reasons.append("At least one device has a completed backup within the last " + window_str + " days")
            pass_reasons.append("Devices with completed backup in window: " + recent_str + " of " + total_str)
            if most_recent:
                pass_reasons.append("Most recent completed backup timestamp: " + most_recent)
        else:
            fail_reasons.append("No devices have a completed backup within the last " + window_str + " days")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            else:
                fail_reasons.append("Devices with completed backup in window: " + recent_str + " of " + total_str)
            recommendations.append("Initiate and verify a full backup cycle on all managed endpoints")
            recommendations.append("Review backup completion logs in the CrashPlan console for any failures")
            recommendations.append("Confirm lastCompletedBackup timestamps are being populated correctly in the Computer resource")
        without_str = str(eval_result.get("devicesWithNoCompletedBackup", 0))
        if eval_result.get("devicesWithNoCompletedBackup", 0) > 0:
            additional_findings.append(without_str + " device(s) have no completed backup within the " + window_str + "-day test window")
        result_dict = {criteriaKey: result_value}
        for k in extra_fields:
            result_dict[k] = extra_fields[k]
        return create_response(
            result=result_dict,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "totalDevices": eval_result.get("totalDevices", 0),
                "devicesWithRecentCompletedBackup": eval_result.get("devicesWithRecentCompletedBackup", 0),
                "testWindowDays": eval_result.get("testWindowDays", 90),
                "mostRecentCompletedBackup": most_recent
            }
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
