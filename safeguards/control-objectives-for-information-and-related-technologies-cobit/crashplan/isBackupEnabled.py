"""
Transformation: isBackupEnabled
Vendor: CrashPlan  |  Category: control-objectives-for-information-and-related-technologies-cobit
Evaluates: Whether CrashPlan backup agents are active and enabled across enrolled devices.
           Checks that at least one active computer is returned from the Computer resource,
           and that enrolled devices have backup usage configured.
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
                "transformationId": "isBackupEnabled",
                "vendor": "CrashPlan",
                "category": "control-objectives-for-information-and-related-technologies-cobit"
            }
        }
    }


def evaluate(data):
    """
    Evaluates whether backup is enabled by inspecting active computers from the
    CrashPlan Computer resource. The API is queried with active=true and incBackupUsage=true,
    so any returned device is an active backup agent. Backup is considered enabled when
    at least one active device is enrolled.
    """
    try:
        computers = data.get("computers", [])
        if not isinstance(computers, list):
            computers = []

        total_devices = len(computers)

        if total_devices == 0:
            return {
                "isBackupEnabled": False,
                "totalDevices": 0,
                "devicesWithBackupUsage": 0,
                "devicesWithoutBackupUsage": 0,
                "backupCoveragePercentage": 0,
                "reason": "No active devices found in CrashPlan"
            }

        devices_with_backup = 0
        devices_without_backup = 0
        for computer in computers:
            backup_usage = computer.get("backupUsage", [])
            if isinstance(backup_usage, list) and len(backup_usage) > 0:
                devices_with_backup = devices_with_backup + 1
            elif isinstance(backup_usage, dict) and backup_usage:
                devices_with_backup = devices_with_backup + 1
            else:
                devices_without_backup = devices_without_backup + 1

        coverage_pct = 0
        if total_devices > 0:
            coverage_pct = int((devices_with_backup * 100) / total_devices)

        is_enabled = total_devices > 0 and devices_with_backup > 0

        return {
            "isBackupEnabled": is_enabled,
            "totalDevices": total_devices,
            "devicesWithBackupUsage": devices_with_backup,
            "devicesWithoutBackupUsage": devices_without_backup,
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

        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        total = eval_result.get("totalDevices", 0)
        with_backup = eval_result.get("devicesWithBackupUsage", 0)
        without_backup = eval_result.get("devicesWithoutBackupUsage", 0)
        coverage = eval_result.get("backupCoveragePercentage", 0)

        if result_value:
            pass_reasons.append(
                "CrashPlan backup is enabled: " + str(with_backup) + " of " + str(total) +
                " active device(s) have backup usage configured (" + str(coverage) + "% coverage)"
            )
        else:
            if total == 0:
                fail_reasons.append("No active devices found enrolled in CrashPlan")
                recommendations.append(
                    "Ensure CrashPlan backup agents are installed and activated on all managed devices"
                )
            else:
                fail_reasons.append(
                    "Backup usage not configured on any of the " + str(total) + " enrolled device(s)"
                )
                recommendations.append(
                    "Configure backup destinations and enable backup for all enrolled CrashPlan devices"
                )
            if "error" in eval_result:
                fail_reasons.append("Evaluation error: " + eval_result["error"])

        if without_backup > 0 and result_value:
            additional_findings.append(
                str(without_backup) + " device(s) are enrolled but have no backup usage configured"
            )
            recommendations.append(
                "Review and configure backup settings for the " + str(without_backup) +
                " device(s) missing backup usage"
            )

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "totalDevices": total,
                "devicesWithBackupUsage": with_backup,
                "devicesWithoutBackupUsage": without_backup,
                "backupCoveragePercentage": coverage
            }
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
