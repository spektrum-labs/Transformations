import json
from datetime import datetime


CRITERIA_KEY = "failedBackupJobsCount"


def error_reason(body):
    """A reason string when the body is an API error or refusal (any 4xx/5xx), else None."""
    if not isinstance(body, dict):
        return None
    for key in ("error", "Error", "errors"):
        err = body.get(key)
        if err:
            return "IDrive API returned an error; " + CRITERIA_KEY + " was not measured."
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

    plans = []
    if isinstance(data, list):
        plans = data
    elif isinstance(data, dict):
        candidate = data.get("data")
        if not isinstance(candidate, list):
            candidate = data.get("apiResponse")
        if not isinstance(candidate, list):
            candidate = data.get("results")
        if isinstance(candidate, list):
            plans = candidate
        elif isinstance(candidate, dict):
            plans = [candidate]

    api_error = error_reason(input) or error_reason(data)
    if api_error:
        plans = []

    total_plans = len(plans)
    failed_count = 0
    plans_with_failures = 0
    plans_without_list = 0
    failed_device_ids = []

    for plan in plans:
        failed_on = plan.get("backup_failed_on") if isinstance(plan, dict) else None
        if not isinstance(failed_on, list):
            # Missing, null or "" backup_failed_on proves nothing about this plan's failures.
            plans_without_list = plans_without_list + 1
            continue
        if len(failed_on) > 0:
            failed_count = failed_count + len(failed_on)
            plans_with_failures = plans_with_failures + 1
            failed_device_ids = failed_device_ids + failed_on

    transformation_errors = []
    if total_plans == 0 and not api_error:
        transformation_errors.append("No backup plan records found in response")

    input_summary = {
        "totalBackupPlansEvaluated": total_plans,
        "plansWithFailures": plans_with_failures,
        "failedBackupJobsCount": failed_count,
    }

    plan_ids = [p.get("id") for p in plans if isinstance(p, dict)]

    result_count = failed_count
    if api_error:
        result_count = None
        pass_reasons = []
        fail_reasons = [api_error]
        recommendations = [
            "Check the IDrive API credentials and permissions for getBackupPlan, then re-run the check."
        ]
    elif total_plans == 0:
        result_count = None
        pass_reasons = []
        fail_reasons = [
            "No backup plan records were returned by the API; failed backup job count could not be determined from any plan data."
        ]
        recommendations = [
            "Verify the company_id is correct and that backup plans exist for this tenant."
        ]
    elif plans_without_list > 0:
        result_count = None
        pass_reasons = []
        fail_reasons = [
            f"{plans_without_list} of {total_plans} backup plan record(s) carry no backup_failed_on list; the failed backup job count cannot be determined, so it is not evaluated."
        ]
        recommendations = [
            "Confirm getBackupPlan returns backup_failed_on for every plan for this tenant."
        ]
    elif failed_count > 0:
        pass_reasons = []
        fail_reasons = [
            f"{failed_count} device(s) across {plans_with_failures} of {total_plans} backup plan(s) ({plan_ids}) are listed in backup_failed_on, indicating failed backup jobs. Device ids: {failed_device_ids}."
        ]
        recommendations = [
            "Investigate the devices listed in backup_failed_on for the affected backup plan(s) and re-run or repair the failed backup jobs."
        ]
    else:
        pass_reasons = [
            f"Evaluated {total_plans} backup plan(s) (plan id(s): {plan_ids}); none report entries in backup_failed_on, so {failed_count} failed backup jobs were found."
        ]
        fail_reasons = []
        recommendations = []

    if result_count is None:
        # Not measured: the derived counts were never read, so they are not 0.
        plans_with_failures = None
        input_summary["failedBackupJobsCount"] = None
        input_summary["plansWithFailures"] = None

    return create_response(
        result={
            "failedBackupJobsCount": result_count,
            "totalBackupPlansEvaluated": total_plans,
            "plansWithFailures": plans_with_failures,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={"transformationId": CRITERIA_KEY, "vendor": "IDrive", "category": "backup"},
        transformation_errors=transformation_errors,
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
