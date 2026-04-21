"""
Transformation: isBackupEnabled
Vendor: AWS  |  Category: nydfs
Evaluates: Whether at least one active AWS Backup plan exists in the account.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isBackupEnabled", "vendor": "AWS", "category": "nydfs"}
        }
    }


def evaluate(data):
    try:
        backup_plans = data.get("BackupPlansList", [])
        if not isinstance(backup_plans, list):
            backup_plans = []
        total_plans = len(backup_plans)
        plan_names = [p.get("BackupPlanName", p.get("BackupPlanId", "unknown")) for p in backup_plans]
        is_enabled = total_plans > 0
        return {
            "isBackupEnabled": is_enabled,
            "totalBackupPlans": total_plans,
            "backupPlanNames": plan_names
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
            return create_response(result={criteriaKey: False}, validation=validation, fail_reasons=["Input validation failed"])
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []
        total_plans = eval_result.get("totalBackupPlans", 0)
        plan_names = eval_result.get("backupPlanNames", [])
        if result_value:
            pass_reasons.append("At least one active AWS Backup plan is configured in this account.")
            pass_reasons.append("Total backup plans found: " + str(total_plans))
            if plan_names:
                additional_findings.append("Backup plans: " + ", ".join([str(n) for n in plan_names]))
        else:
            fail_reasons.append("No AWS Backup plans were found in this account.")
            if "error" in eval_result:
                fail_reasons.append("Evaluation error: " + eval_result["error"])
            recommendations.append("Create at least one AWS Backup plan to protect your resources. Navigate to the AWS Backup console and configure a backup plan with appropriate rules and resource assignments.")
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"totalBackupPlans": total_plans, "isBackupEnabled": result_value}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
