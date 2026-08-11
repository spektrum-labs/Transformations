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


IMPOSTER_KEYWORDS = [
    "imposter",
    "impersonation",
    "impersonate",
    "bec",
    "business email compromise",
    "spoof",
]


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, dict) else {}

    metadata = {
        "transformationId": "isImposterEmailDetectionEnabled",
        "vendor": "Check Point Software Technologies Email Security",
        "category": "emailsecurity",
    }

    # Detect an upstream API error (e.g. auth failure) surfaced directly in the body
    if data.get("error") or data.get("statusCode") == 401 or data.get("status") == "Error":
        err_msg = data.get("errorMessage") or data.get("message") or "Unknown API error"
        return create_response(
            result={"isImposterEmailDetectionEnabled": False},
            validation=validation,
            fail_reasons=[
                f"API call to queryEvents failed with error: {err_msg}. Cannot confirm imposter/phishing detection engine status."
            ],
            recommendations=[
                "Verify API credentials and connectivity to the Check Point Harmony Email and Collaboration event/query endpoint, then re-run the check."
            ],
            input_summary={"apiError": err_msg},
            metadata=metadata,
            api_errors=[err_msg],
        )

    items = data.get("responseData") or []
    if not isinstance(items, list):
        items = []

    envelope = data.get("responseEnvelope") or {}
    total_records = envelope.get("totalRecordsNumber") or len(items)

    phishing_events = []
    imposter_events = []

    for item in items:
        if not isinstance(item, dict):
            continue
        etype = str(item.get("type") or "").lower()
        desc = str(item.get("description") or "").lower()
        if etype == "phishing":
            phishing_events.append(item)
        for kw in IMPOSTER_KEYWORDS:
            if kw in desc or kw in etype:
                imposter_events.append(item)
                break

    enabled = len(phishing_events) > 0 or len(imposter_events) > 0

    input_summary = {
        "totalRecordsNumber": total_records,
        "eventsInPage": len(items),
        "phishingEventsFound": len(phishing_events),
        "imposterKeywordEventsFound": len(imposter_events),
    }

    if enabled:
        sample_ids = [e.get("eventId") for e in (imposter_events or phishing_events)[:3]]
        pass_reasons = [
            f"Found {len(phishing_events)} events of type='Phishing' and {len(imposter_events)} events with imposter/impersonation/BEC-related descriptions (e.g. event IDs {sample_ids}) out of {len(items)} events queried, confirming the AI anti-phishing/impersonation verdict engine is active."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"No Phishing-type or imposter/impersonation-keyword events were found among {len(items)} events returned by the query (totalRecordsNumber={total_records})."
        ]
        recommendations = [
            "Confirm the Anti-Phishing engine is enabled in Harmony Email and Collaboration Security Settings, and re-query /event/query with a broader time range or type filter including 'Phishing'."
        ]

    return create_response(
        result={"isImposterEmailDetectionEnabled": enabled},
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata=metadata,
    )
