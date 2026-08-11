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
    transformation_errors = []

    # Detect vendor-level error envelope (auth failure, etc.)
    if data.get("error") is True or data.get("statusCode") == 401 or data.get("status") == "Error":
        err_msg = data.get("errorMessage") or data.get("message") or "Unknown API error"
        api_errors.append(f"queryEvents returned an error: {err_msg}")
        return create_response(
            result={"isAntiPhishingEnabled": False},
            validation=validation,
            fail_reasons=[
                f"queryEvents API call failed ({err_msg}); unable to confirm anti-phishing detection activity."
            ],
            recommendations=[
                "Verify Check Point HEC API credentials (clientId/clientSecret) are valid and re-run the scan to obtain event data."
            ],
            input_summary={"error": True, "errorMessage": err_msg},
            api_errors=api_errors,
            metadata={"transformationId": "isAntiPhishingEnabled", "vendor": "Check Point Software Technologies Email Security", "category": "emailsecurity"},
        )

    events = data.get("responseData") or []
    if not isinstance(events, list):
        events = []

    phishing_events = []
    for ev in events:
        if not isinstance(ev, dict):
            continue
        event_types = ev.get("eventTypes") or []
        if not isinstance(event_types, list):
            event_types = [event_types]
        for et in event_types:
            if isinstance(et, str) and "phish" in et.lower():
                phishing_events.append(ev)
                break

    total_events = len(events)
    phishing_count = len(phishing_events)
    is_enabled = phishing_count > 0

    input_summary = {"totalEvents": total_events, "phishingEvents": phishing_count}

    if is_enabled:
        sample_ids = [e.get("eventId") for e in phishing_events[:3] if isinstance(e, dict)]
        pass_reasons = [
            f"Found {phishing_count} of {total_events} queried security events with an eventTypes entry containing 'Phishing' (sample eventIds: {sample_ids}), indicating the anti-phishing detection engine is actively scanning and flagging mail."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"No phishing-category detections found among {total_events} queried security events (eventTypes field); cannot confirm the anti-phishing engine is actively scanning mail."
        ]
        recommendations = [
            "Confirm the Harmony Email and Collaboration anti-phishing policy/engine is enabled for this tenant and widen the event query lookback window to capture detections."
        ]

    return create_response(
        result={"isAntiPhishingEnabled": is_enabled},
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        transformation_errors=transformation_errors,
        api_errors=api_errors,
        metadata={"transformationId": "isAntiPhishingEnabled", "vendor": "Check Point Software Technologies Email Security", "category": "emailsecurity"},
    )
