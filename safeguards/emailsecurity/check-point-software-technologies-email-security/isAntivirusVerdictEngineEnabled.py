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
    if data.get("error") is True or data.get("errorType") == "authentication":
        api_errors.append(
            "Vendor API returned an error: %s (status %s)"
            % (data.get("errorMessage") or data.get("message") or "unknown error",
               data.get("statusCode") or "unknown")
        )

    event = data.get("responseData") or {}
    if isinstance(event, list):
        event = event[0] if len(event) > 0 else {}
    if not isinstance(event, dict):
        event = {}

    event_data = event.get("data") or {}
    if not isinstance(event_data, dict):
        event_data = {}

    additional_data = event.get("additionalData") or {}
    if not isinstance(additional_data, dict):
        additional_data = {}

    combined_verdict = event_data.get("combinedVerdict") or additional_data.get("combinedVerdict") or {}
    if not isinstance(combined_verdict, dict):
        combined_verdict = {}

    av_verdict = combined_verdict.get("av")
    has_dedicated_av_verdict = av_verdict is not None and av_verdict != ""

    event_type = event.get("type")
    confidence_indicator = event.get("confidenceIndicator")

    fallback_signal = event_type == "malware" and confidence_indicator is not None

    is_enabled = bool(has_dedicated_av_verdict or fallback_signal)

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if has_dedicated_av_verdict:
        pass_reasons.append(
            "Event %s carries a dedicated combinedVerdict.av value of '%s', independent of any sandbox/ai verdict fields."
            % (event.get("eventId") or "unknown", av_verdict)
        )
    elif fallback_signal:
        pass_reasons.append(
            "Event %s has type='malware' with confidenceIndicator='%s', indicating the anti-malware verdict engine flagged the event, though no explicit combinedVerdict.av field was present in this response."
            % (event.get("eventId") or "unknown", confidence_indicator)
        )
    else:
        fail_reasons.append(
            "No combinedVerdict.av field was found on the event data (combinedVerdict=%s) and event type/confidenceIndicator (%s/%s) did not indicate a malware verdict."
            % (combined_verdict, event_type, confidence_indicator)
        )
        recommendations.append(
            "Verify that a dedicated signature-based antivirus verdict engine is provisioned and returning combinedVerdict.av on scanned events; contact Check Point support if the field is consistently absent."
        )

    if api_errors:
        fail_reasons.append(
            "Could not verify the antivirus verdict engine because the API call failed: %s"
            % "; ".join(api_errors)
        )
        is_enabled = False

    result = {
        "isAntivirusVerdictEngineEnabled": is_enabled,
        "avVerdict": av_verdict,
        "eventType": event_type,
        "confidenceIndicator": confidence_indicator,
    }

    input_summary = {
        "eventId": event.get("eventId"),
        "hasCombinedVerdict": bool(combined_verdict),
        "avVerdictPresent": has_dedicated_av_verdict,
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
            "transformationId": "isAntivirusVerdictEngineEnabled",
            "vendor": "Check Point Software Technologies Email Security",
            "category": "emailsecurity",
        },
    )
