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

    metadata = {
        "transformationId": "isCloudDataLeakPreventionEnabled",
        "vendor": "Check Point Software Technologies Email Security",
        "category": "Email Security",
    }

    # Detect an explicit API/auth error response before attempting to parse events
    if data.get("error") is True or data.get("statusCode") == 401 or data.get("status") == "Error":
        err_msg = data.get("errorMessage") or data.get("message") or "Unknown API error"
        return create_response(
            result={"isCloudDataLeakPreventionEnabled": False},
            validation=validation,
            fail_reasons=[
                f"The queryEvents call returned an error response ('{err_msg}'), so no DLP events could be inspected to confirm the DLP engine is evaluating messages and recording verdicts."
            ],
            recommendations=[
                "Verify the configured clientId/accessKey credentials have permission to call the Harmony Email and Collaboration Event Query API, then re-run this check."
            ],
            input_summary={"apiError": err_msg},
            metadata=metadata,
            api_errors=[err_msg],
        )

    items = data.get("responseData") or []
    if not isinstance(items, list):
        items = []

    envelope = data.get("responseEnvelope") or {}
    total_records = envelope.get("totalRecordsNumber") if isinstance(envelope, dict) else None

    dlp_events = []
    for item in items:
        if not isinstance(item, dict):
            continue
        event_type = str(item.get("type") or "").lower()
        description = str(item.get("description") or "").lower()
        if event_type == "dlp" or "dlp" in event_type or "dlp engine" in description or "data leak" in description:
            dlp_events.append(item)

    input_summary = {
        "totalEventsInPage": len(items),
        "dlpEventsFound": len(dlp_events),
        "totalRecordsNumber": total_records,
    }

    if len(dlp_events) > 0:
        sample = dlp_events[0]
        sample_id = sample.get("eventId") or "unknown"
        sample_desc = sample.get("description") or "DLP Engine detected a leak"
        return create_response(
            result={"isCloudDataLeakPreventionEnabled": True},
            validation=validation,
            pass_reasons=[
                f"queryEvents returned {len(dlp_events)} event(s) of type 'dlp' out of {len(items)} events on this page (e.g. eventId={sample_id}, description='{sample_desc}'), confirming outbound/internal messages are evaluated by the Check Point DLP engine and a verdict is recorded."
            ],
            input_summary=input_summary,
            metadata=metadata,
        )

    # No dlp-type events found in this response
    if len(items) == 0:
        return create_response(
            result={"isCloudDataLeakPreventionEnabled": False},
            validation=validation,
            fail_reasons=[
                "queryEvents returned zero events in responseData, so no DLP verdicts could be observed to confirm the Cloud DLP engine is actively evaluating messages."
            ],
            recommendations=[
                "Confirm the DLP engine is enabled in the Harmony Email and Collaboration policy, and query a broader eventTypes/date range that includes 'dlp' events."
            ],
            input_summary=input_summary,
            metadata=metadata,
        )

    return create_response(
        result={"isCloudDataLeakPreventionEnabled": False},
        validation=validation,
        fail_reasons=[
            f"queryEvents returned {len(items)} event(s) but none had type='dlp' or a DLP-related description, so no DLP verdict enforcement could be confirmed in this sample."
        ],
        recommendations=[
            "Query the Event API with eventTypes filter including 'dlp' to confirm DLP engine verdicts are being recorded, or enable the DLP policy in the Harmony Email and Collaboration console."
        ],
        input_summary=input_summary,
        metadata=metadata,
    )
