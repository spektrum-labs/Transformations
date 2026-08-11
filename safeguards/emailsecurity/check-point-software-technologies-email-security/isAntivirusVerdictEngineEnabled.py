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
        api_errors.append(str(data.get("message") or data.get("errorMessage") or "API error"))

    events = data.get("responseData") or []
    if not isinstance(events, list):
        events = []

    malware_events = []
    for ev in events:
        if not isinstance(ev, dict):
            continue
        ev_type = str(ev.get("type") or "").strip().lower()
        if ev_type == "malware":
            malware_events.append(ev)

    total_malware = len(malware_events)
    events_with_av_verdict = 0
    sample_verdicts = []
    for ev in malware_events:
        combined_verdict = ev.get("combinedVerdict")
        av_verdict = None
        if isinstance(combined_verdict, dict):
            av_verdict = combined_verdict.get("av")
        if av_verdict is not None and av_verdict != "":
            events_with_av_verdict = events_with_av_verdict + 1
            if len(sample_verdicts) < 3:
                sample_verdicts.append(f"eventId={ev.get('eventId')} combinedVerdict.av={av_verdict}")

    is_enabled = events_with_av_verdict > 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_enabled:
        pass_reasons.append(
            f"Found {events_with_av_verdict} of {total_malware} Malware-type events with a populated "
            f"combinedVerdict.av field, confirming a dedicated signature-based AV verdict is recorded "
            f"independent of sandbox/AI verdicts. Samples: {'; '.join(sample_verdicts)}"
        )
    else:
        if total_malware > 0:
            fail_reasons.append(
                f"Queried {total_malware} Malware-type events but none carried a populated "
                f"combinedVerdict.av field."
            )
            recommendations.append(
                "Verify the antivirus/signature-based verdict engine is enabled in the Harmony Email "
                "and Collaboration security policy so combinedVerdict.av is populated on malware events."
            )
        else:
            fail_reasons.append(
                "No Malware-type events were returned by /event/query, so combinedVerdict.av "
                "presence could not be confirmed for this tenant window."
            )
            recommendations.append(
                "Confirm API credentials are valid and re-run the query over a broader time window "
                "or across all customers to capture malware-type events with combinedVerdict.av."
            )

    if api_errors:
        fail_reasons.append(f"API returned an error before data could be evaluated: {'; '.join(api_errors)}")
        recommendations.append("Resolve API authentication/connectivity issues (check clientId/clientSecret) so /event/query returns event data.")

    result = {
        "isAntivirusVerdictEngineEnabled": is_enabled,
        "totalMalwareEvents": total_malware,
        "malwareEventsWithAvVerdict": events_with_av_verdict,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalEvents": len(events), "malwareEvents": total_malware},
        metadata={
            "transformationId": "isAntivirusVerdictEngineEnabled",
            "vendor": "Check Point Software Technologies Email Security",
            "category": "emailsecurity",
        },
        api_errors=api_errors,
    )
