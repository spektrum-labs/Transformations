"""
Transformation: isBackupEnabled
Vendor: CrashPlan  |  Category: nydfs
Evaluates: Whether the majority of active managed devices have CrashPlan backup actively running,
as evidenced by non-empty backupUsage arrays with at least one non-null lastBackup timestamp.
"""
import json
from datetime import datetime


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
                "transformationId": "isBackupEnabled",
                "vendor": "CrashPlan",
                "category": "nydfs"
            }
        }
    }


def computer_has_active_backup(computer):
    backup_usage = computer.get("backupUsage", [])
    if not backup_usage:
        return False
    for entry in backup_usage:
        if entry.get("lastBackup") is not None:
            return True
    return False


def evaluate(data):
    try:
        computers = data.get("computers", [])
        total_count = len(computers)
        if total_count == 0:
            return {
                "isBackupEnabled": False,
                "totalDevices": 0,
                "devicesWithBackup": 0,
                "devicesWithoutBackup": 0,
                "backupCoveragePercentage": 0,
                "error": "No active computers found in the CrashPlan environment"
            }
        devices_with_backup = 0
        devices_without_backup = 0
        for computer in computers:
            if computer_has_active_backup(computer):
                devices_with_backup = devices_with_backup + 1
            else:
                devices_without_backup = devices_without_backup + 1
        coverage_pct = (devices_with_backup * 100) // total_count
        is_enabled = devices_with_backup > (total_count // 2)
        return {
            "isBackupEnabled": is_enabled,
            "totalDevices": total_count,
            "devicesWithBackup": devices_with_backup,
            "devicesWithoutBackup": devices_without_backup,
            "backupCoveragePercentage": coverage_pct
        }
    except Exception as e:
        return {"isBackupEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isBackupEnabled"
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
        total_str = str(eval_result.get("totalDevices", 0))
        with_str = str(eval_result.get("devicesWithBackup", 0))
        pct_str = str(eval_result.get("backupCoveragePercentage", 0))
        if result_value:
            pass_reasons.append("CrashPlan backup is actively enabled on the majority of managed devices")
            pass_reasons.append("Devices with active backup: " + with_str + " of " + total_str)
            pass_reasons.append("Backup coverage: " + pct_str + "%")
        else:
            fail_reasons.append("CrashPlan backup is not enabled on the majority of active managed devices")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            else:
                fail_reasons.append("Devices with backup: " + with_str + " of " + total_str)
                fail_reasons.append("Backup coverage: " + pct_str + "%")
            recommendations.append("Ensure CrashPlan is installed and running on all managed endpoints")
            recommendations.append("Investigate devices without backup activity and remediate configuration issues")
        without_str = str(eval_result.get("devicesWithoutBackup", 0))
        if eval_result.get("devicesWithoutBackup", 0) > 0:
            additional_findings.append(without_str + " device(s) have no recorded backup activity")
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
                "devicesWithBackup": eval_result.get("devicesWithBackup", 0),
                "backupCoveragePercentage": eval_result.get("backupCoveragePercentage", 0)
            }
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
