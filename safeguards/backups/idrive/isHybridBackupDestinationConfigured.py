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
        plans = data.get("data") or data.get("apiResponse") or []
        if not isinstance(plans, list):
            plans = [plans] if isinstance(plans, dict) else []
    else:
        plans = []

    total_plans = len(plans)
    hybrid_plans = []
    non_hybrid_plans = []

    for plan in plans:
        if not isinstance(plan, dict):
            continue
        plan_id = plan.get("id") or plan.get("name") or "unknown"
        backup_details = plan.get("backup_details") or {}
        where_to_backup = backup_details.get("where_to_backup")

        destinations = set()
        if isinstance(where_to_backup, list):
            for d in where_to_backup:
                if isinstance(d, str):
                    destinations.add(d.strip().upper())
        elif isinstance(where_to_backup, str):
            for part in where_to_backup.split(","):
                part = part.strip().upper()
                if part:
                    destinations.add(part)

        has_cloud = "CLOUD" in destinations
        has_local = "LOCAL" in destinations

        if has_cloud and has_local:
            hybrid_plans.append({"id": plan_id, "where_to_backup": where_to_backup})
        else:
            non_hybrid_plans.append({"id": plan_id, "where_to_backup": where_to_backup})

    is_hybrid_configured = total_plans > 0 and len(hybrid_plans) > 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_hybrid_configured:
        names = ", ".join([str(p.get("id")) for p in hybrid_plans])
        pass_reasons.append(
            f"{len(hybrid_plans)} of {total_plans} backup plan(s) (plan id(s): {names}) "
            f"report backup_details.where_to_backup containing both CLOUD and LOCAL destinations."
        )
    else:
        if total_plans == 0:
            fail_reasons.append("No backup plans were returned by getBackupPlan; hybrid destination status cannot be confirmed.")
            recommendations.append("Verify that at least one backup plan exists and is retrievable via the API.")
        else:
            observed = ", ".join([f"{p.get('id')}={p.get('where_to_backup')}" for p in non_hybrid_plans])
            fail_reasons.append(
                f"None of the {total_plans} backup plan(s) configure both CLOUD and LOCAL destinations "
                f"(observed where_to_backup values: {observed})."
            )
            recommendations.append(
                "Configure the backup plan's where_to_backup setting to include both CLOUD and LOCAL "
                "destinations to enable hybrid backup for this device."
            )

    result = {
        "isHybridBackupDestinationConfigured": is_hybrid_configured,
        "totalBackupPlans": total_plans,
        "hybridBackupPlansCount": len(hybrid_plans),
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalBackupPlans": total_plans, "hybridBackupPlansCount": len(hybrid_plans)},
        metadata={
            "transformationId": "isHybridBackupDestinationConfigured",
            "vendor": "IDrive",
            "category": "backup",
        },
    )
