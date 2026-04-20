"""
Transformation: isBackupEnabled
Vendor: CrashPlan  |  Category: nist-sp-800-53-rev-5-security-and-privacy-controls
Evaluates: Whether CrashPlan backup agents are deployed and active across the environment,
           determined by inspecting the GET /api/v1/Computer response (active=true,
           incBackupUsage=true) for a non-empty set of active computers.
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
                "transformationId": "isBackupEnabled",
                "vendor": "CrashPlan",
                "category": "nist-sp-800-53-rev-5-security-and-privacy-controls"
            }
        }
    }


def evaluate(data):
    """
    Inspect the merged getComputers data.
    Passes when at least one active computer is present (backup agents deployed).
    Also reports counts and how many computers have backup usage data.
    """
    try:
        computers = data.get("computers", [])
        if not isinstance(computers, list):
            computers = []

        total_computers = len(computers)

        if total_computers == 0:
            return {
                "isBackupEnabled": False,
                "totalComputers": 0,
                "activeComputers": 0,
                "computersWithBackupUsage": 0,
                "error": "No active computers found in CrashPlan — backup agents may not be deployed"
            }

        active_computers = 0
        computers_with_backup_usage = 0

        for computer in computers:
            is_active = computer.get("active", False)
            if is_active:
                active_computers = active_computers + 1
            backup_usage = computer.get("backupUsage", [])
            if isinstance(backup_usage, list) and len(backup_usage) > 0:
                computers_with_backup_usage = computers_with_backup_usage + 1

        is_enabled = active_computers > 0

        return {
            "isBackupEnabled": is_enabled,
            "totalComputers": total_computers,
            "activeComputers": active_computers,
            "computersWithBackupUsage": computers_with_backup_usage
        }
    except Exception as e:
        return {"isBackupEnabled": False, "error": str(e)}


def transform(input):
    criteria_key = "isBackupEnabled"
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

        total = eval_result.get("totalComputers", 0)
        active = eval_result.get("activeComputers", 0)
        with_usage = eval_result.get("computersWithBackupUsage", 0)

        if result_value:
            pass_reasons.append(
                "Backup agents are deployed and active: " + str(active) +
                " active computer(s) out of " + str(total) + " total"
            )
            if with_usage > 0:
                pass_reasons.append(
                    str(with_usage) + " computer(s) have backup usage data recorded"
                )
        else:
            fail_reasons.append(
                "No active computers found in CrashPlan — backup is not confirmed as enabled"
            )
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append(
                "Ensure CrashPlan backup agents are installed and active on all managed devices"
            )
            recommendations.append(
                "Verify that the API credentials have permission to read the Computer resource"
            )

        if total > 0 and with_usage < total:
            not_reporting = total - with_usage
            additional_findings.append(
                str(not_reporting) + " computer(s) have no backup usage data — they may not have completed a backup yet"
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
