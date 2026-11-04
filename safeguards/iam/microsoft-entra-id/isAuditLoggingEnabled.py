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
        audit_events = data
    elif isinstance(data, dict):
        audit_events = data.get("value") or []
        if not isinstance(audit_events, list):
            audit_events = []
    else:
        audit_events = []

    total_events = len(audit_events)

    valid_events = []
    for event in audit_events:
        if not isinstance(event, dict):
            continue
        activity_name = event.get("activityDisplayName")
        activity_date = event.get("activityDateTime")
        category = event.get("category")
        result_field = event.get("result")
        if activity_date:
            valid_events.append({
                "activityDisplayName": activity_name,
                "activityDateTime": activity_date,
                "category": category,
                "result": result_field,
            })

    is_enabled = len(valid_events) > 0

    sample = valid_events[0] if valid_events else None

    if is_enabled:
        sample_desc = ""
        if sample:
            sample_desc = (
                f"Most recent event: '{sample.get('activityDisplayName')}' "
                f"in category '{sample.get('category')}' at {sample.get('activityDateTime')} "
                f"with result '{sample.get('result')}'."
            )
        pass_reasons = [
            f"Directory audit log feed (/auditLogs/directoryAudits) returned {total_events} "
            f"event(s) with populated activityDateTime timestamps, indicating audit logging "
            f"is actively capturing directory events for this tenant. {sample_desc}"
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"Directory audit log feed (/auditLogs/directoryAudits) returned {total_events} "
            f"event(s), none of which carried a populated activityDateTime, so no evidence "
            f"of active audit logging was found."
        ]
        recommendations = [
            "Verify that Microsoft Entra ID directory audit logging is enabled for the "
            "tenant and that the audit log retention/diagnostic settings are configured "
            "to capture directory events."
        ]

    result = {
        "isAuditLoggingEnabled": is_enabled,
        "totalAuditEvents": total_events,
        "validAuditEvents": len(valid_events),
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalAuditEvents": total_events, "validAuditEvents": len(valid_events)},
        metadata={
            "transformationId": "isAuditLoggingEnabled",
            "vendor": "Microsoft Entra ID",
            "category": "iam",
        },
    )
