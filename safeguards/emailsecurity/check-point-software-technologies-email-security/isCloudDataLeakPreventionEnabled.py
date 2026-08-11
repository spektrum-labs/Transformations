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


DLP_TYPE_LABELS = ["dlp", "data leak prevention", "data loss prevention"]


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, dict) else {}

    api_errors = []
    if data.get("error") is True or data.get("status") == "Error":
        error_message = data.get("errorMessage") or data.get("message") or "Unknown API error"
        api_errors.append(f"queryEvents API error: {error_message}")

    response_data = data.get("responseData") or []
    if not isinstance(response_data, list):
        response_data = []

    dlp_events = []
    for event in response_data:
        if not isinstance(event, dict):
            continue
        event_type = str(event.get("type") or "").strip().lower()
        if event_type in DLP_TYPE_LABELS:
            dlp_events.append(event)

    dlp_events_with_verdict = [
        e for e in dlp_events
        if e.get("state") or e.get("confidenceIndicator") or e.get("severity")
    ]

    total_dlp = len(dlp_events)
    total_with_verdict = len(dlp_events_with_verdict)

    is_enabled = total_dlp > 0 and total_with_verdict > 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if api_errors:
        fail_reasons.append(
            f"queryEvents returned an authentication/API error, so no DLP event evidence could be retrieved: {api_errors[0]}"
        )
        recommendations.append(
            "Verify the OAuth clientId/clientSecret credentials configured for this integration and re-run the scan against the /event/query endpoint."
        )
    elif is_enabled:
        sample = dlp_events_with_verdict[0]
        pass_reasons.append(
            f"Found {total_dlp} event(s) of type='dlp' in the queried event set, and {total_with_verdict} of them carry a recorded verdict "
            f"(state='{sample.get('state')}', confidenceIndicator='{sample.get('confidenceIndicator')}', severity='{sample.get('severity')}'), "
            "confirming the DLP engine evaluated messages and recorded a verdict."
        )
    else:
        fail_reasons.append(
            f"No events of type='dlp' with a recorded state/confidenceIndicator/severity were found among {len(response_data)} queried events."
        )
        recommendations.append(
            "Confirm the Check Point DLP engine is enabled for this tenant and that outbound/internal messages are being scanned; "
            "re-query /event/query with a broader time range or filter to type='dlp' to verify."
        )

    result = {
        "isCloudDataLeakPreventionEnabled": is_enabled,
        "totalDlpEvents": total_dlp,
        "dlpEventsWithVerdict": total_with_verdict,
    }

    input_summary = {
        "totalEventsQueried": len(response_data),
        "totalDlpEvents": total_dlp,
        "dlpEventsWithVerdict": total_with_verdict,
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
            "transformationId": "isCloudDataLeakPreventionEnabled",
            "vendor": "Check Point Software Technologies Email Security",
            "category": "Email Security",
        },
    )
