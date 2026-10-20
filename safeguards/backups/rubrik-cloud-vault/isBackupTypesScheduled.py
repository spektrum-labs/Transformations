"""Transformation: isBackupTypesScheduled (Rubrik Cloud Vault, getSnappables)"""
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
        nodes = data
    elif isinstance(data, dict):
        conn = data.get("snappableConnection") or data.get("data", {}).get("snappableConnection") if isinstance(data.get("data"), dict) else data.get("snappableConnection")
        if not conn:
            conn = data.get("snappableConnection") or {}
        nodes = conn.get("nodes") or [] if isinstance(conn, dict) else []
    else:
        nodes = []

    total = len(nodes)
    scheduled_count = 0
    unscheduled_names = []

    for node in nodes:
        if not isinstance(node, dict):
            continue
        sla = node.get("slaDomain")
        protection_status = node.get("protectionStatus") or ""
        has_sla = False
        if isinstance(sla, dict):
            sla_id = sla.get("id")
            sla_name = sla.get("name") or ""
            if sla_id and sla_name.upper() != "UNPROTECTED" and sla_name.upper() != "DO_NOT_PROTECT":
                has_sla = True
        if protection_status.upper() in ("UNPROTECTED", "DO_NOT_PROTECT"):
            has_sla = False
        if has_sla:
            scheduled_count = scheduled_count + 1
        else:
            name = node.get("name") or node.get("id") or "unknown"
            if len(unscheduled_names) < 5:
                unscheduled_names.append(name)

    is_scheduled = scheduled_count > 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if total == 0:
        fail_reasons.append("No snappable objects were returned in the getSnappables response, so no SLA domain / snapshot schedule assignment could be verified.")
        recommendations.append("Verify getSnappables returns data and that objects are onboarded to Rubrik protection.")
        is_scheduled = False
    elif is_scheduled:
        pass_reasons.append(
            f"{scheduled_count} of {total} sampled snappable objects carry a non-null slaDomain (id present, name not UNPROTECTED/DO_NOT_PROTECT), indicating an SLA Domain with a defined snapshot schedule (e.g. hourly/daily/weekly cadence) is attached."
        )
    else:
        fail_reasons.append(
            f"None of the {total} sampled snappable objects have a valid slaDomain assignment (protectionStatus indicates UNPROTECTED/DO_NOT_PROTECT or slaDomain missing). Examples: {', '.join(unscheduled_names) if unscheduled_names else 'n/a'}."
        )
        recommendations.append("Assign an SLA Domain with a configured snapshot schedule (hourly/daily/weekly) to the unprotected objects.")

    result = {
        "isBackupTypesScheduled": is_scheduled,
        "totalSnappables": total,
        "snappablesWithScheduledSla": scheduled_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalSnappables": total, "snappablesWithScheduledSla": scheduled_count},
        metadata={
            "transformationId": "isBackupTypesScheduled",
            "vendor": "Rubrik Cloud Vault",
            "category": "backup",
        },
    )
