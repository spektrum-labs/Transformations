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
    if data.get("error") is True or data.get("statusCode") == 401 or data.get("status") == "Error":
        err_msg = data.get("errorMessage") or data.get("message") or "Unknown API error"
        api_errors.append(f"queryEvents API call failed: {err_msg}")

    response_data = data.get("responseData") or []
    if not isinstance(response_data, list):
        response_data = []

    response_envelope = data.get("responseEnvelope") or {}
    total_records = response_envelope.get("totalRecordsNumber") if isinstance(response_envelope, dict) else None

    ato_related_types = ["anomaly", "account takeover", "login anomaly", "impossible travel", "suspicious login"]

    ato_events = []
    for event in response_data:
        if not isinstance(event, dict):
            continue
        event_type = str(event.get("type") or "").lower()
        description = str(event.get("description") or "").lower()
        if any(t in event_type for t in ato_related_types) or "account takeover" in description or "anomaly" in description:
            ato_events.append(event)

    is_enabled = len(ato_events) > 0

    input_summary = {
        "totalEventsReturned": len(response_data),
        "totalRecordsInEnvelope": total_records,
        "atoRelatedEventsFound": len(ato_events),
    }

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if api_errors:
        fail_reasons.append(
            "Unable to confirm account takeover detection: the queryEvents API call returned an authentication "
            "error and no event data could be evaluated."
        )
        recommendations.append(
            "Verify the Check Point Harmony Email and Collaboration API credentials (clientId/clientSecret) "
            "and re-run the query against /event/query filtering for anomaly-type events."
        )
    elif is_enabled:
        sample_types = list({str(e.get("type")) for e in ato_events[:5]})
        pass_reasons.append(
            f"Found {len(ato_events)} event(s) with anomaly/account-takeover characteristics out of "
            f"{len(response_data)} events returned by queryEvents (sample types: {sample_types}). "
            "This evidences the account takeover / anomaly detection engine is active and generating detections."
        )
    else:
        fail_reasons.append(
            f"queryEvents returned {len(response_data)} events, none of which matched anomaly/account-takeover "
            "type or description markers (e.g. 'Anomaly', 'account takeover', 'impossible travel'). No evidence "
            "the ATO detection engine has produced any detections."
        )
        recommendations.append(
            "Confirm the Anomaly detection engine is enabled in Harmony Email and Collaboration security engine "
            "settings, and query /event/query with a broader time range or explicit type filter for 'Anomaly'."
        )

    result = {
        "isAccountTakeoverDetectionEnabled": is_enabled,
        "atoRelatedEventsFound": len(ato_events),
        "totalEventsReturned": len(response_data),
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        api_errors=api_errors,
        metadata={
            "transformationId": "isAccountTakeoverDetectionEnabled",
            "vendor": "Check Point Software Technologies Email Security",
            "category": "emailsecurity",
        },
    )
