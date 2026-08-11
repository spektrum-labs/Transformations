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


ATTACHMENT_KEYWORDS = ["attachment", "malware", "sandbox", "detonation", "malicious file"]


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, dict) else {}

    api_errors = []
    if data.get("error") is True or data.get("errorType") == "authentication" or data.get("statusCode") == 401:
        api_errors.append(
            "queryEvents returned an authentication/error response: %s"
            % data.get("errorMessage", data.get("message", "unknown error"))
        )
        result = {
            "isSafeAttachmentsEnabled": False,
            "eventsInspected": 0,
            "attachmentDetections": 0,
        }
        return create_response(
            result=result,
            validation=validation,
            fail_reasons=[
                "queryEvents API call failed with error: %s. Unable to confirm Safe Attachments detonation activity."
                % data.get("errorMessage", data.get("message", "unknown error"))
            ],
            recommendations=[
                "Verify clientId/clientSecret credentials and re-run the /event/query scan to confirm Safe Attachments detection activity."
            ],
            input_summary={"eventsInspected": 0, "attachmentDetections": 0},
            api_errors=api_errors,
            metadata={
                "transformationId": "isSafeAttachmentsEnabled",
                "vendor": "Check Point Software Technologies Email Security",
                "category": "emailsecurity",
            },
        )

    events = data.get("responseData") or []
    if not isinstance(events, list):
        events = []

    attachment_detections = 0
    sample_event_ids = []
    for ev in events:
        if not isinstance(ev, dict):
            continue
        event_types = ev.get("eventTypes") or []
        if not isinstance(event_types, list):
            event_types = [event_types]
        attachments = ev.get("attachments") or []
        has_attachment_type = False
        for et in event_types:
            et_str = str(et).lower()
            for kw in ATTACHMENT_KEYWORDS:
                if kw in et_str:
                    has_attachment_type = True
                    break
            if has_attachment_type:
                break
        if has_attachment_type and isinstance(attachments, list) and len(attachments) > 0:
            attachment_detections = attachment_detections + 1
            if len(sample_event_ids) < 3:
                sample_event_ids.append(ev.get("eventId"))

    total_events = len(events)
    enabled = attachment_detections > 0

    input_summary = {
        "eventsInspected": total_events,
        "attachmentDetections": attachment_detections,
    }

    result = {
        "isSafeAttachmentsEnabled": enabled,
        "eventsInspected": total_events,
        "attachmentDetections": attachment_detections,
    }

    if enabled:
        pass_reasons = [
            "Found %d of %d queried security events with attachment-related eventTypes (e.g. malware/sandbox/detonation keywords) and non-empty attachments arrays; sample eventIds: %s. This indicates the attachment-sandboxing/detonation engine is actively scanning and flagging malicious attachments."
            % (attachment_detections, total_events, sample_event_ids)
        ]
        return create_response(
            result=result,
            validation=validation,
            pass_reasons=pass_reasons,
            input_summary=input_summary,
            metadata={
                "transformationId": "isSafeAttachmentsEnabled",
                "vendor": "Check Point Software Technologies Email Security",
                "category": "emailsecurity",
            },
        )
    else:
        fail_reasons = [
            "Queried %d security events from /event/query and found 0 events with attachment-related eventTypes and populated attachments arrays. No evidence of active Safe Attachments detonation/blocking activity in this response window."
            % total_events
        ]
        recommendations = [
            "Confirm Safe Attachments / attachment-sandboxing policy is enabled in the Harmony Email & Collaboration console, and re-query /event/query over a longer lookback window to capture detonation events."
        ]
        return create_response(
            result=result,
            validation=validation,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary=input_summary,
            metadata={
                "transformationId": "isSafeAttachmentsEnabled",
                "vendor": "Check Point Software Technologies Email Security",
                "category": "emailsecurity",
            },
        )
