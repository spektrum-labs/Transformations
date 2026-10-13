
import json
from datetime import datetime


CRITERIA_KEY = "backupSuccessRatePercentage"


def error_reason(body):
    """A reason string when the body is an API error or refusal (any 4xx/5xx), else None."""
    if not isinstance(body, dict):
        return None
    for key in ("error", "Error", "errors"):
        err = body.get(key)
        if err:
            return "IDrive API returned an error; " + CRITERIA_KEY + " was not measured: " + str(err)[:200]
    for key in ("statusCode", "status_code", "status", "httpStatus"):
        code = body.get(key)
        if isinstance(code, int) and not isinstance(code, bool) and code >= 400:
            return "IDrive API returned HTTP " + str(code) + "; " + CRITERIA_KEY + " was not measured."
    return None


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
        plans = data.get("data") or data.get("results") or []
        if not isinstance(plans, list):
            plans = []
    else:
        plans = []

    api_error = error_reason(input) or error_reason(data)
    if api_error:
        plans = []

    total_applied = 0
    total_failed = 0
    total_pending = 0
    plan_count = 0
    plans_without_lists = 0

    for plan in plans:
        plan_count = plan_count + 1
        if not isinstance(plan, dict):
            plans_without_lists = plans_without_lists + 1
            continue
        applied = plan.get("backup_applied_on")
        failed = plan.get("backup_failed_on")
        pending = plan.get("backup_pending_on") or []
        if not isinstance(applied, list) or not isinstance(failed, list):
            # Missing, null or "" applied/failed lists prove nothing about this plan's outcomes.
            plans_without_lists = plans_without_lists + 1
            continue
        if not isinstance(pending, list):
            pending = []
        total_applied = total_applied + len(applied)
        total_failed = total_failed + len(failed)
        total_pending = total_pending + len(pending)

    attempted = total_applied + total_failed

    if api_error or plan_count == 0 or plans_without_lists > 0 or attempted == 0:
        # No completed attempt to divide by, or an incomplete read: the rate is not measured.
        success_rate = None
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

    if api_error:
        fail_reasons.append(api_error)
        recommendations.append("Check the IDrive API credentials and permissions for getBackupPlan, then re-run the check.")
    elif plan_count == 0:
        fail_reasons.append("No backup plans were returned by getBackupPlan; success rate cannot be computed.")
        recommendations.append("Verify at least one backup plan is configured and applied to devices for this company.")
    elif plans_without_lists > 0:
        fail_reasons.append(
            f"{plans_without_lists} of {plan_count} backup plan record(s) carry no backup_applied_on/backup_failed_on lists; the success rate cannot be computed, so it is not evaluated."
        )
        recommendations.append("Confirm getBackupPlan returns backup_applied_on and backup_failed_on for every plan for this company.")
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
        api_errors=[api_error] if api_error else None,
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
