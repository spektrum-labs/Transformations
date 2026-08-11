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
    if data.get("error") is True or data.get("statusCode") == 401:
        api_errors.append(str(data.get("errorMessage") or data.get("message") or "API error"))
        return create_response(
            result={"isSafeLinksEnabled": False},
            validation=validation,
            fail_reasons=["queryEvents call returned an authentication/API error: %s" % (data.get("errorMessage") or data.get("message") or "unknown error")],
            recommendations=["Verify clientId/clientSecret credentials and re-authenticate to the Harmony Email and Collaboration API so event telemetry can be retrieved."],
            input_summary={"error": True, "statusCode": data.get("statusCode")},
            api_errors=api_errors,
            metadata={
                "transformationId": "isSafeLinksEnabled",
                "vendor": "Check Point Software Technologies Email Security",
                "category": "emailsecurity",
            },
        )

    events = data.get("responseData") or []
    if not isinstance(events, list):
        events = []

    link_event_count = 0
    total_events = len(events)
    sample_event_ids = []
    for ev in events:
        if not isinstance(ev, dict):
            continue
        event_types = ev.get("eventTypes") or []
        links = ev.get("links") or []
        is_link_related = False
        for et in event_types:
            if isinstance(et, str) and ("link" in et.lower() or "url" in et.lower() or "phish" in et.lower()):
                is_link_related = True
                break
        if not is_link_related and links:
            is_link_related = True
        if is_link_related:
            link_event_count = link_event_count + 1
            if len(sample_event_ids) < 5:
                sample_event_ids.append(ev.get("eventId"))

    is_enabled = link_event_count > 0

    input_summary = {
        "totalEvents": total_events,
        "linkRelatedEventCount": link_event_count,
    }

    if is_enabled:
        pass_reasons = [
            "Found %d of %d queried security events with link-related eventTypes or populated links fields (sample eventIds: %s), indicating the Safe Links / URL scanning engine is actively detecting and acting on malicious links." % (link_event_count, total_events, sample_event_ids)
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            "No link-related detections found among %d queried security events (no eventTypes containing 'link'/'url'/'phish' and no populated links arrays), so no evidence the Safe Links / URL scanning engine is enabled or generating detections." % total_events
        ]
        recommendations = [
            "Confirm Safe Links / URL protection is enabled in the Harmony Email and Collaboration policy configuration and widen the event query lookback window to capture link-based detections."
        ]

    return create_response(
        result={"isSafeLinksEnabled": is_enabled},
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isSafeLinksEnabled",
            "vendor": "Check Point Software Technologies Email Security",
            "category": "emailsecurity",
        },
    )
