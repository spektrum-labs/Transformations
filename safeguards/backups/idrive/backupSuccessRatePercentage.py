
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
        plans = data.get("data") or data.get("results") or []
        if not isinstance(plans, list):
            plans = []
    else:
        plans = []

    total_applied = 0
    total_failed = 0
    total_pending = 0
    plan_count = 0

    for plan in plans:
        if not isinstance(plan, dict):
            continue
        plan_count = plan_count + 1
        applied = plan.get("backup_applied_on") or []
        failed = plan.get("backup_failed_on") or []
        pending = plan.get("backup_pending_on") or []
        if not isinstance(applied, list):
            applied = []
        if not isinstance(failed, list):
            failed = []
        if not isinstance(pending, list):
            pending = []
        total_applied = total_applied + len(applied)
        total_failed = total_failed + len(failed)
        total_pending = total_pending + len(pending)

    attempted = total_applied + total_failed

    if attempted == 0:
        success_rate = 0
    else:
        success_rate = round((total_applied / attempted) * 100.0, 2)

    input_summary = {
        "planCount": plan_count,
        "totalApplied": total_applied,
        "totalFailed": total_failed,
        "totalPending": total_pending,
        "attempted": attempted,
    }

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if plan_count == 0:
        fail_reasons.append("No backup plans were returned by getBackupPlan; success rate cannot be computed.")
        recommendations.append("Verify at least one backup plan is configured and applied to devices for this company.")
    elif attempted == 0:
        fail_reasons.append(
            f"Across {plan_count} backup plan(s), no devices appear in backup_applied_on or backup_failed_on (both empty); no completed backup attempts to evaluate."
        )
        recommendations.append("Confirm backup plans have been applied to devices and jobs have run at least once.")
    else:
        pass_reasons.append(
            f"Across {plan_count} backup plan(s), {total_applied} of {attempted} attempted device backups completed successfully (backup_applied_on vs backup_failed_on), a {success_rate}% success rate. {total_pending} device(s) remain pending application."
        )
        if total_failed > 0:
            fail_reasons.append(
                f"{total_failed} device backup(s) are listed in backup_failed_on across the plan(s) evaluated."
            )
            recommendations.append("Investigate devices listed in backup_failed_on for recurring backup failures.")

    result = {
        "backupSuccessRatePercentage": success_rate,
        "totalApplied": total_applied,
        "totalFailed": total_failed,
        "totalPending": total_pending,
        "planCount": plan_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={"transformationId": "backupSuccessRatePercentage", "vendor": "IDrive", "category": "backup"},
    )
