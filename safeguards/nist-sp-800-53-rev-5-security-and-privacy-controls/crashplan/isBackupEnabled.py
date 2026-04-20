"""
Transformation: isBackupEnabled
Vendor: CrashPlan  |  Category: nist-sp-800-53-rev-5-security-and-privacy-controls
Evaluates: Whether backup is actively enabled across enrolled CrashPlan devices.
Uses the Computer resource (active=true, incBackupUsage=true). A device is considered
backup-enabled when its 'active' field is true, 'blocked' is false, and the 'backupUsage'
array is non-empty. Pass condition: majority of active computers have a populated backupUsage.
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
                "transformationId": "isBackupEnabled",
                "vendor": "CrashPlan",
                "category": "nist-sp-800-53-rev-5-security-and-privacy-controls"
            }
        }
    }


def evaluate(data):
    try:
        computers = data.get("computers", [])
        if not isinstance(computers, list):
            computers = []

        total = len(computers)
        if total == 0:
            return {
                "isBackupEnabled": False,
                "totalComputers": 0,
                "enabledCount": 0,
                "disabledCount": 0,
                "scoreInPercentage": 0,
                "error": "No computers found in API response"
            }

        enabled_count = 0
        disabled_devices = []

        for computer in computers:
            active = computer.get("active", False)
            blocked = computer.get("blocked", False)
            backup_usage = computer.get("backupUsage", [])
            if not isinstance(backup_usage, list):
                backup_usage = []
            if active and not blocked and len(backup_usage) > 0:
                enabled_count = enabled_count + 1
            else:
                device_name = computer.get("name", computer.get("computerName", "unknown"))
                disabled_devices.append(str(device_name))

        score = (enabled_count * 100) // total
        is_enabled = enabled_count > (total // 2)

        result = {
            "isBackupEnabled": is_enabled,
            "totalComputers": total,
            "enabledCount": enabled_count,
            "disabledCount": total - enabled_count,
            "scoreInPercentage": score
        }
        if disabled_devices:
            result["devicesWithoutBackup"] = disabled_devices[:10]
        return result
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
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []
        total = eval_result.get("totalComputers", 0)
        enabled = eval_result.get("enabledCount", 0)
        score = eval_result.get("scoreInPercentage", 0)
        if result_value:
            pass_reasons.append("Backup is enabled on the majority of enrolled CrashPlan devices.")
            pass_reasons.append(
                str(enabled) + " of " + str(total) + " computers have backup enabled (" + str(score) + "%)."
            )
        else:
            fail_reasons.append("Backup is not enabled on the majority of enrolled CrashPlan devices.")
            fail_reasons.append(
                str(enabled) + " of " + str(total) + " computers have backup enabled (" + str(score) + "%)."
            )
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append(
                "Ensure all active CrashPlan devices have at least one configured backup destination."
            )
            recommendations.append(
                "Review blocked or inactive devices and reconfigure backup destinations as needed."
            )
        if "devicesWithoutBackup" in eval_result:
            additional_findings.append(
                "Devices without backup (up to 10): " + ", ".join(eval_result["devicesWithoutBackup"])
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
            input_summary={"totalComputers": total, "enabledCount": enabled, "scoreInPercentage": score}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
