import json
from datetime import datetime


CRITERIA_KEY = "isBackupEnabled"


def extract_input(input_data):
    """Extract data and validation from input, handling enriched + legacy formats."""
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
    """Create the standardized 5-section transformation response."""
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
        plans = data.get("data") or data.get("apiResponse") or data.get("plans") or []
        if not isinstance(plans, list):
            plans = [plans] if isinstance(plans, dict) else []
    else:
        plans = []

    total_plans = len(plans)
    enabled_plans = []
    disabled_plans = []
    plans_with_flag = 0

    for plan in plans:
        if not isinstance(plan, dict):
            continue
        enabled_flag = plan.get("is_backup_enabled")
        if enabled_flag is None:
            enabled_flag = plan.get("is_enabled")
        if enabled_flag is not None:
            plans_with_flag += 1
        plan_name = plan.get("name") or plan.get("id") or "unknown plan"
        if enabled_flag:
            enabled_plans.append(plan_name)
        else:
            disabled_plans.append(plan_name)

    is_backup_enabled = total_plans > 0 and len(enabled_plans) > 0
    if plans_with_flag == 0:
        # No plan, or no plan carrying is_enabled/is_backup_enabled (empty body, refusal,
        # status stub): nothing was measured, so the criterion is None, not False.
        is_backup_enabled = None

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if total_plans == 0:
        fail_reasons.append("No backup plans were returned by getBackupPlan for this company; cannot confirm backup is enabled.")
        recommendations.append("Verify at least one backup plan is configured for this company in IDrive 360.")
    elif is_backup_enabled is None:
        fail_reasons.append("No backup plan in the response carries is_enabled/is_backup_enabled; cannot confirm backup is enabled.")
    elif is_backup_enabled:
        pass_reasons.append(
            f"{len(enabled_plans)} of {total_plans} backup plan(s) report enabled status (is_enabled/is_backup_enabled=true): {', '.join(enabled_plans)}."
        )
        if disabled_plans:
            pass_reasons.append(
                f"Note: {len(disabled_plans)} plan(s) are disabled: {', '.join(disabled_plans)}."
            )
    else:
        fail_reasons.append(
            f"All {total_plans} backup plan(s) report is_enabled/is_backup_enabled=false: {', '.join(disabled_plans)}."
        )
        recommendations.append("Enable the backup plan(s) in the IDrive 360 console for this company.")

    result = {
        "isBackupEnabled": is_backup_enabled,
        "totalBackupPlans": total_plans,
        "enabledBackupPlansCount": len(enabled_plans),
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalBackupPlans": total_plans, "enabledBackupPlansCount": len(enabled_plans)},
        metadata={
            "transformationId": "isBackupEnabled",
            "vendor": "IDrive",
            "category": "backup",
        },
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
