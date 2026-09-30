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

    total_plans = len(plans)
    failed_count = 0
    plans_with_failures = 0
    failed_device_ids = []

    for plan in plans:
        if not isinstance(plan, dict):
            continue
        failed_on = plan.get("backup_failed_on")
        if isinstance(failed_on, list) and len(failed_on) > 0:
            failed_count = failed_count + len(failed_on)
            plans_with_failures = plans_with_failures + 1
            failed_device_ids = failed_device_ids + failed_on

    transformation_errors = []
    if total_plans == 0:
        transformation_errors.append("No backup plan records found in response")

    input_summary = {
        "totalBackupPlansEvaluated": total_plans,
        "plansWithFailures": plans_with_failures,
        "failedBackupJobsCount": failed_count,
    }

    plan_ids = [p.get("id") for p in plans if isinstance(p, dict)]

    if total_plans == 0:
        pass_reasons = []
        fail_reasons = [
            "No backup plan records were returned by the API; failed backup job count could not be determined from any plan data."
        ]
        recommendations = [
            "Verify the company_id is correct and that backup plans exist for this tenant."
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

    return create_response(
        result={
            "failedBackupJobsCount": failed_count,
            "totalBackupPlansEvaluated": total_plans,
            "plansWithFailures": plans_with_failures,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        transformation_errors=transformation_errors,
    )
