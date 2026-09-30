
import json
from datetime import datetime


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
            plans = [plans] if plans else []
    else:
        plans = []

    total_plans = len(plans)
    configured_plans = []
    unconfigured_plans = []

    for plan in plans:
        if not isinstance(plan, dict):
            continue
        schedule_info = plan.get("schedule_info") or {}
        email = schedule_info.get("email") if isinstance(schedule_info, dict) else None
        plan_name = plan.get("name") or plan.get("id") or "unnamed plan"
        if email and isinstance(email, str) and email.strip() != "":
            configured_plans.append(plan_name)
        else:
            unconfigured_plans.append(plan_name)

    is_configured = total_plans > 0 and len(configured_plans) > 0

    if total_plans == 0:
        fail_reasons = ["No backup plans were returned by getBackupPlan, so no failure-alert recipient could be verified."]
        pass_reasons = []
        recommendations = ["Verify at least one backup plan exists and configure schedule_info.email with a recipient address."]
    elif is_configured:
        pass_reasons = [
            f"{len(configured_plans)} of {total_plans} backup plan(s) have a non-empty schedule_info.email recipient configured (e.g. plan(s): {', '.join(configured_plans)})."
        ]
        fail_reasons = []
        recommendations = []
        if unconfigured_plans:
            recommendations.append(
                f"Configure schedule_info.email for the remaining plan(s) without a recipient: {', '.join(unconfigured_plans)}."
            )
    else:
        pass_reasons = []
        fail_reasons = [
            f"All {total_plans} backup plan(s) have an empty schedule_info.email field, so no failure-alert recipient is configured (plan(s): {', '.join(unconfigured_plans)})."
        ]
        recommendations = ["Set schedule_info.email on the backup plan to a valid recipient address so failure notifications can be delivered."]

    result = {
        "isBackupFailureAlertRecipientConfigured": is_configured,
        "totalBackupPlans": total_plans,
        "plansWithRecipientConfigured": len(configured_plans),
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalBackupPlans": total_plans, "configuredPlans": len(configured_plans)},
        metadata={
            "transformationId": "isBackupFailureAlertRecipientConfigured",
            "vendor": "IDrive",
            "category": "backup",
        },
    )
