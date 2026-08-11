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
    if data.get("error") or data.get("errorType") == "authentication" or data.get("statusCode") == 401:
        api_errors.append(
            "API returned authentication error: %s" % data.get("message", data.get("errorMessage", "unknown error"))
        )
        return create_response(
            result={"isAntiPhishingEnabled": False},
            validation=validation,
            fail_reasons=["Could not retrieve event data from queryEvents due to an authentication error; anti-phishing status could not be confirmed."],
            recommendations=["Verify API credentials (clientId/clientSecret) and re-run the scan to confirm anti-phishing engine activity."],
            input_summary={"apiError": True},
            api_errors=api_errors,
            metadata={"transformationId": "isAntiPhishingEnabled", "vendor": "Check Point Software Technologies Email Security", "category": "emailsecurity"},
        )

    events = data.get("responseData") or []
    if not isinstance(events, list):
        events = []

    response_envelope = data.get("responseEnvelope") or {}
    total_records = response_envelope.get("totalRecordsNumber") or 0

    phishing_events = []
    for e in events:
        if not isinstance(e, dict):
            continue
        etype = e.get("type") or ""
        if isinstance(etype, str) and "phish" in etype.lower():
            phishing_events.append(e)

    phishing_count = len(phishing_events)
    is_enabled = phishing_count > 0

    sample_ids = [e.get("eventId") for e in phishing_events[:5]]

    if is_enabled:
        pass_reasons = [
            "queryEvents returned %d event(s) with type containing 'Phishing' out of %d events in this response (sample eventIds: %s), evidencing the anti-phishing detection engine is active." % (
                phishing_count, len(events), sample_ids
            )
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            "No events with type containing 'Phishing' were found among the %d event(s) returned by queryEvents (responseEnvelope.totalRecordsNumber=%s)." % (
                len(events), total_records
            )
        ]
        recommendations = [
            "Confirm the Anti-Phishing security engine is enabled in Harmony Email and Collaboration policy settings, or broaden the /event/query filter criteria to include a longer time window."
        ]

    return create_response(
        result={
            "isAntiPhishingEnabled": is_enabled,
            "phishingEventCount": phishing_count,
            "totalEventsInResponse": len(events),
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalEventsInResponse": len(events), "phishingEventCount": phishing_count, "totalRecordsNumber": total_records},
        metadata={"transformationId": "isAntiPhishingEnabled", "vendor": "Check Point Software Technologies Email Security", "category": "emailsecurity"},
    )
