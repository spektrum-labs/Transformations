"""Transformation: isMissedScheduledBackupAutoResumeEnabled"""
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
                if key in data and isinstance(data.get(key), (dict, list)):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped or not isinstance(data, dict):
                break
    validation = {
        "status": "unknown",
        "errors": [],
        "warnings": ["Legacy input format - no schema validation performed"],
    }
    return data, validation


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None,
                    transformation_errors=None, api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    transform_err_list = transformation_errors or []
    data_collection_status = "error" if api_err_list else "success"
    transformation_status = "error" if transform_err_list else "success"
    response_metadata = {
        "evaluatedAt": datetime.utcnow().isoformat() + "Z",
        "schemaVersion": "2.0",
    }
    if metadata:
        response_metadata.update(metadata)
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": data_collection_status, "errors": api_err_list},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": transformation_status,
                "errors": transform_err_list,
                "inputSummary": input_summary or {},
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or [],
            },
            "metadata": response_metadata,
        },
    }


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    if isinstance(data, list):
        plans = data
    elif isinstance(data, dict):
        plans = data.get("data") or data.get("apiResponse") or data.get("results") or []
        if not isinstance(plans, list):
            plans = [plans] if isinstance(plans, dict) else []
    else:
        plans = []

    total_plans = len(plans)
    plans_with_auto_resume = []
    plans_without_auto_resume = []

    for plan in plans:
        if not isinstance(plan, dict):
            continue
        schedule_info = plan.get("schedule_info") or {}
        start_missed_backup = schedule_info.get("start_missed_backup")
        plan_name = plan.get("name") or plan.get("id") or "unnamed plan"
        if start_missed_backup is True:
            plans_with_auto_resume.append(plan_name)
        else:
            plans_without_auto_resume.append(plan_name)

    all_enabled = total_plans > 0 and len(plans_without_auto_resume) == 0

    result = {
        "isMissedScheduledBackupAutoResumeEnabled": all_enabled,
        "totalPlans": total_plans,
        "plansWithAutoResume": len(plans_with_auto_resume),
        "plansWithoutAutoResume": len(plans_without_auto_resume),
    }

    if total_plans == 0:
        pass_reasons = []
        fail_reasons = ["No backup plans were returned by getBackupPlan, so schedule_info.start_missed_backup could not be evaluated for any plan."]
        recommendations = ["Verify that at least one backup plan is configured for this company and retry."]
    elif all_enabled:
        pass_reasons = [
            f"All {total_plans} backup plan(s) have schedule_info.start_missed_backup=true "
            f"({', '.join(plans_with_auto_resume)}), meaning a missed scheduled backup "
            f"(e.g. device powered off) will automatically resume."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"{len(plans_without_auto_resume)} of {total_plans} backup plan(s) have "
            f"schedule_info.start_missed_backup=false ({', '.join(plans_without_auto_resume)}), "
            f"meaning missed scheduled backups will NOT automatically resume."
        ]
        recommendations = [
            f"Enable 'start_missed_backup' on the following backup plan(s): {', '.join(plans_without_auto_resume)}."
        ]

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalPlans": total_plans,
            "plansWithAutoResume": len(plans_with_auto_resume),
            "plansWithoutAutoResume": len(plans_without_auto_resume),
        },
        metadata={"transformationId": "isMissedScheduledBackupAutoResumeEnabled", "vendor": "IDrive", "category": "backup"},
    )
