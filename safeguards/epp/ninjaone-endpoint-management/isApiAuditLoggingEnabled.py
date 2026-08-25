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
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
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
    data = data if isinstance(data, dict) else {}

    results = data.get("results") or []
    if not isinstance(results, list):
        results = []

    total_activities = len(results)

    # Count activities that actually carry audit-trail metadata (activityType +
    # activityTime + a subject/message describing the action). Presence of the
    # 'results'/'cursor' envelope keys alone is NOT evidence of audit logging --
    # only records with real audit content prove the trail is being captured.
    valid_entries = 0
    distinct_types = set()
    distinct_sources = set()
    for r in results:
        if not isinstance(r, dict):
            continue
        activity_type = r.get("activityType")
        activity_time = r.get("activityTime")
        has_narrative = bool(r.get("subject") or r.get("message"))
        if activity_type and activity_time and has_narrative:
            valid_entries = valid_entries + 1
            distinct_types.add(activity_type)
            source_type = r.get("sourceType")
            if source_type:
                distinct_sources.add(source_type)

    fail_reasons = []
    pass_reasons = []
    recommendations = []

    if total_activities == 0:
        is_enabled = False
        fail_reasons.append(
            "The /v2/activities feed returned 0 activity records for this scan window, "
            "so no evidence of a per-device or tenant-wide audit trail could be confirmed."
        )
        recommendations.append(
            "Verify that NinjaOne activity logging is active for this tenant and that "
            "devices are reporting configuration-change and action events to the Activities feed."
        )
    elif valid_entries == 0:
        is_enabled = False
        fail_reasons.append(
            f"{total_activities} activity record(s) were returned, but none carried a "
            "populated activityType, activityTime, and subject/message together, so the "
            "records do not constitute a usable audit trail."
        )
        recommendations.append(
            "Confirm activity logging captures full metadata (activityType, activityTime, "
            "subject/message) for configuration changes and actions."
        )
    else:
        is_enabled = True
        sample_types = ", ".join(sorted(distinct_types)[:5])
        sample_sources = ", ".join(sorted(distinct_sources)[:5])
        pass_reasons.append(
            f"{valid_entries} of {total_activities} activity record(s) carry populated "
            f"activityType/activityTime/subject-message fields, covering activity types "
            f"[{sample_types}] from sources [{sample_sources}], confirming NinjaOne is "
            "capturing a per-device and tenant-wide audit trail of actions/changes."
        )

    result = {
        "isApiAuditLoggingEnabled": is_enabled,
        "totalActivities": total_activities,
        "auditableActivities": valid_entries,
    }

    input_summary = {
        "totalActivities": total_activities,
        "auditableActivities": valid_entries,
        "distinctActivityTypes": len(distinct_types),
        "distinctSourceTypes": len(distinct_sources),
    }

    metadata = {
        "transformationId": "isApiAuditLoggingEnabled",
        "vendor": "NinjaOne Endpoint Management",
        "category": "epp",
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata=metadata,
    )
