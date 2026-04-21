"""
Transformation: isBackupEnabledForCriticalSystems
Vendor: CrashPlan  |  Category: Backups
Evaluates: Calculates the coverage percentage of active devices with backup enabled.
Returns True if at least 80% of active devices have backup configured.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isBackupEnabledForCriticalSystems", "vendor": "CrashPlan", "category": "Backups"}
        }
    }


def evaluate(data):
    """
    Core evaluation logic for isBackupEnabledForCriticalSystems.
    Iterates the computers list and determines what fraction of active devices
    have backup configured. Passes when coverage reaches or exceeds 80%.
    """
    try:
        computers = data.get("computers", None)
        if computers is None:
            computers = data.get("data", None)
        if computers is None:
            computers = data.get("items", [])

        total_devices = 0
        active_devices = 0
        devices_with_backup = 0
        devices_connected = 0
        excluded_statuses = ["deactivated", "deauthorized", "blocked"]
        connected_statuses = ["connected", "connectedbackingup", "idle"]

        if isinstance(computers, list):
            total_devices = len(computers)
            for computer in computers:
                is_active = computer.get("active", False)
                status = computer.get("status", "").lower()
                last_connected = computer.get("lastConnected", None)
                backup_usage = computer.get("backupUsage", [])

                if is_active and status not in excluded_statuses:
                    active_devices = active_devices + 1

                    if status in connected_statuses:
                        devices_connected = devices_connected + 1

                    if backup_usage:
                        devices_with_backup = devices_with_backup + 1
                    elif last_connected:
                        devices_with_backup = devices_with_backup + 1

        elif isinstance(data.get("totalCount", None), int):
            total_devices = data.get("totalCount", 0)
            active_devices = total_devices
            devices_with_backup = total_devices

        coverage_percentage = 0.0
        if active_devices > 0:
            coverage_percentage = round((devices_with_backup / active_devices) * 100, 2)

        is_enabled = coverage_percentage >= 80.0 or (active_devices > 0 and devices_with_backup == active_devices)

        return {
            "isBackupEnabledForCriticalSystems": is_enabled,
            "coveragePercentage": coverage_percentage,
            "totalDevices": total_devices,
            "activeDevices": active_devices,
            "devicesWithBackup": devices_with_backup,
            "devicesConnected": devices_connected
        }
    except Exception as e:
        return {"isBackupEnabledForCriticalSystems": False, "error": str(e)}


def transform(input):
    criteriaKey = "isBackupEnabledForCriticalSystems"
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

        coverage = eval_result.get("coveragePercentage", 0.0)
        active = eval_result.get("activeDevices", 0)
        with_backup = eval_result.get("devicesWithBackup", 0)
        total = eval_result.get("totalDevices", 0)

        additional_findings.append("Total devices: " + str(total))
        additional_findings.append("Active devices: " + str(active))
        additional_findings.append("Devices with backup: " + str(with_backup))
        additional_findings.append("Coverage: " + str(coverage) + "%")

        if result_value:
            pass_reasons.append("Backup coverage meets or exceeds the 80% threshold for critical systems")
            pass_reasons.append("Coverage percentage: " + str(coverage) + "%")
            pass_reasons.append(str(with_backup) + " of " + str(active) + " active devices have backup enabled")
        else:
            fail_reasons.append("Backup coverage is below the 80% threshold for critical systems")
            fail_reasons.append("Coverage percentage: " + str(coverage) + "%")
            fail_reasons.append(str(with_backup) + " of " + str(active) + " active devices have backup enabled")
            if active == 0:
                fail_reasons.append("No active devices found in CrashPlan")
                recommendations.append("Ensure devices are enrolled and active in CrashPlan")
            else:
                recommendations.append("Review devices that are active but do not have backup configured and ensure CrashPlan agents are properly deployed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])

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
            input_summary={
                "totalDevices": total,
                "activeDevices": active,
                "devicesWithBackup": with_backup,
                "coveragePercentage": coverage
            }
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
