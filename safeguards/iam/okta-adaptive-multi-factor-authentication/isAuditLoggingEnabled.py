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
        entries = data
    elif isinstance(data, dict):
        entries = data.get("data") or data.get("apiResponse") or []
        if not isinstance(entries, list):
            entries = []
    else:
        entries = []

    total_entries = len(entries)

    valid_entries = []
    for e in entries:
        if not isinstance(e, dict):
            continue
        if e.get("uuid") and e.get("eventType") and e.get("published"):
            valid_entries.append(e)

    is_enabled = len(valid_entries) > 0

    sample = valid_entries[0] if valid_entries else {}
    sample_event_type = sample.get("eventType", "")
    sample_published = sample.get("published", "")
    sample_actor = ""
    actor_obj = sample.get("actor") or {}
    if isinstance(actor_obj, dict):
        sample_actor = actor_obj.get("displayName", "")

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_enabled:
        pass_reasons.append(
            "System Log API (/api/v1/logs) returned %d recorded audit event(s); most recent event uuid=%s, eventType=%s, published=%s, actor=%s."
            % (total_entries, sample.get("uuid", ""), sample_event_type, sample_published, sample_actor)
        )
    else:
        fail_reasons.append(
            "System Log API (/api/v1/logs) returned no recognizable audit log entries (0 records with uuid/eventType/published) out of %d raw entries."
            % total_entries
        )
        recommendations.append(
            "Verify the API token has access to the System Log API and that audit events are being generated for this Okta org."
        )

    result = {
        "isAuditLoggingEnabled": is_enabled,
        "totalLogEntriesReturned": total_entries,
        "validLogEntries": len(valid_entries),
    }

    input_summary = {
        "totalLogEntriesReturned": total_entries,
        "validLogEntries": len(valid_entries),
        "sampleEventType": sample_event_type,
        "samplePublished": sample_published,
    }

    metadata = {
        "transformationId": "isAuditLoggingEnabled",
        "vendor": "Okta Adaptive Multi Factor Authentication",
        "category": "iam",
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
