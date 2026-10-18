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
        plans = data.get("data") or data.get("apiResponse") or []
        if not isinstance(plans, list):
            plans = [plans] if isinstance(plans, dict) else []
    else:
        plans = []

    total_plans = len(plans)
    cdp_enabled_plans = []
    plan_names = []

    for plan in plans:
        if not isinstance(plan, dict):
            continue
        name = plan.get("name") or plan.get("id") or "unknown"
        plan_names.append(name)
        if plan.get("cdp_enabled") is True:
            cdp_enabled_plans.append(name)

    is_forever_incremental = len(cdp_enabled_plans) > 0

    input_summary = {
        "totalPlans": total_plans,
        "plansWithCdpEnabled": len(cdp_enabled_plans),
    }

    if total_plans == 0:
        pass_reasons = []
        fail_reasons = ["No backup plans were returned by getBackupPlan, so forever-incremental (cdp_enabled) status cannot be confirmed."]
        recommendations = ["Configure at least one backup plan and enable continuous data protection (cdp_enabled) if forever-incremental backups are required."]
    elif is_forever_incremental:
        pass_reasons = [
            f"{len(cdp_enabled_plans)} of {total_plans} backup plan(s) have cdp_enabled=true (plans: {', '.join([str(n) for n in cdp_enabled_plans])}), indicating continuous/forever-incremental data protection is active."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"None of the {total_plans} backup plan(s) (plans: {', '.join([str(n) for n in plan_names])}) have cdp_enabled=true; backups are not configured for forever-incremental/continuous data protection."
        ]
        recommendations = ["Enable continuous data protection (cdp_enabled) on the backup plan to achieve forever-incremental (only-changed-data) transfer after the initial full backup."]

    return create_response(
        result={
            "isForeverIncrementalBackupEnabled": is_forever_incremental,
            "totalPlans": total_plans,
            "plansWithCdpEnabled": len(cdp_enabled_plans),
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={"transformationId": "isForeverIncrementalBackupEnabled", "vendor": "IDrive", "category": "backup"},
    )
