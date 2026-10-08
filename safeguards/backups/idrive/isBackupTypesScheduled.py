import json
from datetime import datetime


CRITERIA_KEY = "isBackupTypesScheduled"


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
    # Value-keyed: the verdict is measured only when the criterion carries a value. None means
    # the body proved nothing (empty, refusal, missing field, transform raised) and must not be graded.
    value = result.get(CRITERIA_KEY) if isinstance(result, dict) else None
    measured = value is not None
    api_err_list = [] if measured else (api_errors or transformation_errors or fail_reasons
                                        or [CRITERIA_KEY + " could not be measured from the response"])
    transform_err_list = transformation_errors or []
    data_collection_status = "success" if measured else "error"
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


def evaluate(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    if isinstance(data, list):
        plans = data
    elif isinstance(data, dict):
        plans = data.get("data") or data.get("apiResponse") or data.get("results") or []
        if not isinstance(plans, list):
            plans = []
    else:
        plans = []

    recurring_types = ("DAILY", "WEEKLY", "MONTHLY", "HOURLY")

    total_plans = len(plans)
    enabled_recurring_plans = []
    manual_only_plans = []
    plan_details = []

    for plan in plans:
        if not isinstance(plan, dict):
            continue
        plan_id = plan.get("id") or plan.get("name") or "unknown"
        is_enabled = bool(plan.get("is_enabled") or plan.get("is_backup_enabled") or False)
        schedule_info = plan.get("schedule_info") or {}
        if not isinstance(schedule_info, dict):
            schedule_info = {}
        frequency_type = schedule_info.get("frequency_type") or ""
        frequency_type_upper = frequency_type.upper() if isinstance(frequency_type, str) else ""
        is_recurring = frequency_type_upper in recurring_types

        plan_details.append({
            "id": plan_id,
            "is_enabled": is_enabled,
            "frequency_type": frequency_type_upper,
        })

        if is_enabled and is_recurring:
            enabled_recurring_plans.append(plan_id)
        elif is_enabled and not is_recurring:
            manual_only_plans.append(plan_id)

    # Single source of truth for the criterion value: derived purely from
    # inspecting the actual payload, never hardcoded.
    is_scheduled = len(enabled_recurring_plans) > 0

    input_summary = {
        "totalPlans": total_plans,
        "enabledRecurringPlans": len(enabled_recurring_plans),
        "manualOnlyEnabledPlans": len(manual_only_plans),
        "planDetails": plan_details,
    }

    if len(plan_details) == 0:
        # No plan objects (empty body, refusal, status stub): nothing was measured.
        return create_response(
            result={"isBackupTypesScheduled": None},
            validation=validation,
            fail_reasons=["No backup plans were returned by getBackupPlan; cannot confirm a recurring schedule exists."],
            recommendations=["Verify at least one backup plan is configured for this company."],
            input_summary=input_summary,
        )

    if is_scheduled:
        sample = enabled_recurring_plans[0]
        matched = None
        for p in plan_details:
            if p["id"] == sample:
                matched = p
                break
        freq = matched["frequency_type"] if matched else "UNKNOWN"
        return create_response(
            result={"isBackupTypesScheduled": is_scheduled},
            validation=validation,
            pass_reasons=[
                f"Plan(s) {enabled_recurring_plans} are enabled (is_enabled=true) with schedule_info.frequency_type='{freq}', indicating a recurring backup schedule rather than manual-only backups."
            ],
            input_summary=input_summary,
        )
    else:
        reasons = []
        if manual_only_plans:
            reasons.append(
                f"Plan(s) {manual_only_plans} are enabled but schedule_info.frequency_type is not a recurring value (e.g. MANUAL/blank), so backups are not scheduled."
            )
        else:
            reasons.append(
                "No enabled backup plan has a recurring schedule_info.frequency_type (DAILY/WEEKLY/MONTHLY/HOURLY)."
            )
        return create_response(
            result={"isBackupTypesScheduled": is_scheduled},
            validation=validation,
            fail_reasons=reasons,
            recommendations=["Configure the backup plan's schedule_info.frequency_type to a recurring value (e.g. DAILY or WEEKLY) instead of manual-only."],
            input_summary=input_summary,
        )


def transform(input):
    try:
        return evaluate(input)
    except Exception as e:
        return create_response(
            result={CRITERIA_KEY: None},
            fail_reasons=["Transformation error: " + str(e)],
            transformation_errors=["Transformation error: " + str(e)],
            metadata={"transformationId": CRITERIA_KEY, "vendor": "IDrive", "category": "backup"},
        )
