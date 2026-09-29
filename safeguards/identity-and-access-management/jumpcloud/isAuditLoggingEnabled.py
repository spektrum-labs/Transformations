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
        events = data
    elif isinstance(data, dict):
        events = data.get("apiResponse") or data.get("data") or []
        if not isinstance(events, list):
            events = []
    else:
        events = []

    total_events = len(events)

    # Count events with the key audit-trail fields populated (id, timestamp, event_type)
    valid_audit_events = 0
    event_type_samples = []
    for ev in events:
        if not isinstance(ev, dict):
            continue
        has_id = bool(ev.get("id"))
        has_ts = bool(ev.get("timestamp"))
        has_type = bool(ev.get("event_type"))
        if has_id and has_ts and has_type:
            valid_audit_events = valid_audit_events + 1
            et = ev.get("event_type")
            if et and et not in event_type_samples and len(event_type_samples) < 5:
                event_type_samples.append(et)

    is_enabled = total_events > 0 and valid_audit_events > 0

    input_summary = {
        "totalEventsReturned": total_events,
        "validAuditEvents": valid_audit_events,
        "sampleEventTypes": event_type_samples,
    }

    if is_enabled:
        pass_reasons = [
            f"Directory Insights /events endpoint returned {total_events} events for the tenant, "
            f"of which {valid_audit_events} carry id, timestamp, and event_type fields "
            f"(sample event types: {', '.join(event_type_samples) if event_type_samples else 'n/a'}), "
            f"demonstrating that directory audit logging is active and capturing activity."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"Directory Insights /events endpoint returned {total_events} events for the tenant "
            f"in the queried window, with {valid_audit_events} carrying complete audit fields "
            f"(id, timestamp, event_type). No evidence of active audit logging was found."
        ]
        recommendations = [
            "Verify that Directory Insights is enabled for this JumpCloud organization and that "
            "the API key has permission to read the /insights/directory/v1/events endpoint."
        ]

    result = {
        "isAuditLoggingEnabled": is_enabled,
        "totalEventsReturned": total_events,
        "validAuditEvents": valid_audit_events,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isAuditLoggingEnabled",
            "vendor": "JumpCloud",
            "category": "identity-and-access-management",
        },
    )
