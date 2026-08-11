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

    api_errors = []
    if data.get("error") is True or data.get("statusCode") == 401 or data.get("errorType") == "authentication":
        api_errors.append(str(data.get("errorMessage") or data.get("message") or "API error"))

    response_envelope = data.get("responseEnvelope") or {}
    events = data.get("responseData") or []
    if not isinstance(events, list):
        events = []

    total_records = response_envelope.get("totalRecordsNumber")
    if total_records is None:
        total_records = len(events)

    sample_event = events[0] if events else {}
    event_id = sample_event.get("eventId")
    entity_id = sample_event.get("entityId")
    event_type = sample_event.get("type")
    description = sample_event.get("description")

    sweep_enabled = False
    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if api_errors:
        fail_reasons.append(
            "queryEvents returned an authentication/API error (%s); could not confirm the flexible event-query "
            "sweep capability against the tenant." % (data.get("errorMessage") or data.get("message") or "unknown error")
        )
        recommendations.append(
            "Verify the clientId/clientSecret credentials configured for the Check Point Harmony Email integration "
            "have permission to call POST /event/query, then re-run the sweep confirmation."
        )
    elif events:
        sweep_enabled = True
        pass_reasons.append(
            "POST /event/query returned %d event(s) (sample eventId=%s, entityId=%s, type=%s), confirming the "
            "flexible query API can retrieve historical events across the mailbox estate by criteria such as "
            "indicator, entity, or type -- the mechanism analysts use to sweep for an indicator retroactively."
            % (total_records, event_id, entity_id, event_type)
        )
        if description:
            pass_reasons.append("Sample event description: %s" % description)
    elif "responseEnvelope" in data or "responseData" in data:
        sweep_enabled = True
        pass_reasons.append(
            "POST /event/query responded successfully with a valid responseEnvelope/responseData structure "
            "(totalRecordsNumber=%s), confirming the flexible query mechanism is reachable even though no events "
            "matched this particular query window." % str(total_records)
        )
    else:
        fail_reasons.append(
            "queryEvents response did not include a recognizable responseEnvelope/responseData structure; "
            "unable to confirm the historical-event sweep/search capability is functioning."
        )
        recommendations.append(
            "Confirm the Harmony Email and Collaboration event/query API is enabled for this tenant and that "
            "credentials are valid, then retry the sweep confirmation query."
        )

    result = {
        "isThreatInvestigationSweepEnabled": sweep_enabled,
        "totalRecordsMatched": total_records,
        "sampleEventId": event_id,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"eventCount": len(events), "totalRecordsMatched": total_records},
        api_errors=api_errors,
        metadata={
            "transformationId": "isThreatInvestigationSweepEnabled",
            "vendor": "Check Point Software Technologies Email Security",
            "category": "emailsecurity",
        },
    )
