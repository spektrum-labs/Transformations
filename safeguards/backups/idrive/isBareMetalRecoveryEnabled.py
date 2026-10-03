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
            plans = []
    else:
        plans = []

    total_plans = len(plans)
    entire_machine_plans = []
    entire_machine_enabled_plans = []

    for plan in plans:
        if not isinstance(plan, dict):
            continue
        backup_details = plan.get("backup_details") or {}
        what_to_backup = backup_details.get("what_to_backup") if isinstance(backup_details, dict) else None
        if what_to_backup == "ENTIRE_MACHINE":
            entire_machine_plans.append(plan)
            if plan.get("is_enabled"):
                entire_machine_enabled_plans.append(plan)

    is_enabled = len(entire_machine_enabled_plans) > 0

    input_summary = {
        "totalPlans": total_plans,
        "entireMachinePlans": len(entire_machine_plans),
        "entireMachineEnabledPlans": len(entire_machine_enabled_plans),
    }

    if is_enabled:
        names = [p.get("name") or p.get("id") or "unknown" for p in entire_machine_enabled_plans]
        pass_reasons = [
            "Found %d backup plan(s) with backup_details.what_to_backup='ENTIRE_MACHINE' and is_enabled=true: %s" % (
                len(entire_machine_enabled_plans), ", ".join([str(n) for n in names])
            )
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        if total_plans == 0:
            fail_reasons = ["No backup plans were returned by the API for this company."]
        elif len(entire_machine_plans) == 0:
            backup_types = [
                (p.get("backup_details") or {}).get("what_to_backup") for p in plans if isinstance(p, dict)
            ]
            fail_reasons = [
                "None of the %d backup plan(s) are configured for ENTIRE_MACHINE (bare metal) backup; found types: %s" % (
                    total_plans, ", ".join([str(t) for t in backup_types])
                )
            ]
        else:
            fail_reasons = [
                "Found %d plan(s) configured for ENTIRE_MACHINE backup, but none are enabled (is_enabled=false)." % len(entire_machine_plans)
            ]
        recommendations = [
            "Configure and enable at least one backup plan with 'Entire Machine' (bare metal) selected as the backup type for at least one protected device."
        ]

    result = {
        "isBareMetalRecoveryEnabled": is_enabled,
        "totalPlans": total_plans,
        "entireMachineEnabledPlans": len(entire_machine_enabled_plans),
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isBareMetalRecoveryEnabled",
            "vendor": "IDrive",
            "category": "backup",
        },
    )
