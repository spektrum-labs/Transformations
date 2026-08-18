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
    fail_reasons = []
    pass_reasons = []
    recommendations = []

    is_error = bool(data.get("error"))
    status_code = data.get("statusCode")
    error_type = data.get("errorType")

    if is_error:
        api_errors.append(
            f"queryEvents returned error=true, errorType={error_type}, statusCode={status_code}"
        )
        fail_reasons.append(
            f"queryEvents (POST /app/hec-api/v1.0/event/query) returned an error response "
            f"(errorType={error_type}, statusCode={status_code}), so the ability to sweep/search "
            f"historical events by indicator could not be confirmed."
        )
        recommendations.append(
            "Verify the configured clientId/accessKey credentials have permission to call the "
            "Event Query API, then re-run the scan to confirm sweep capability."
        )
        result = {
            "isThreatInvestigationSweepEnabled": False,
            "eventsReturned": 0,
        }
        return create_response(
            result=result,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"error": is_error, "statusCode": status_code},
            api_errors=api_errors,
            metadata={
                "transformationId": "isThreatInvestigationSweepEnabled",
                "vendor": "Check Point Software Technologies Email Security",
                "category": "emailsecurity",
            },
        )

    response_envelope = data.get("responseEnvelope") or {}
    response_data = data.get("responseData") or []
    if not isinstance(response_data, list):
        response_data = []

    total_records = response_envelope.get("totalRecordsNumber")
    events_returned = len(response_data)

    envelope_present = bool(response_envelope) or "responseData" in data

    if envelope_present:
        pass_reasons.append(
            f"queryEvents (POST /app/hec-api/v1.0/event/query) responded with a valid "
            f"responseEnvelope/responseData structure ({events_returned} event(s) returned"
            + (f", totalRecordsNumber={total_records}" if total_records is not None else "")
            + "), confirming the flexible historical event-query/sweep mechanism is reachable "
              "and functional for retroactive indicator searches across the mailbox estate."
        )
        result = {
            "isThreatInvestigationSweepEnabled": True,
            "eventsReturned": events_returned,
        }
        if total_records is not None:
            result["totalRecordsNumber"] = total_records
    else:
        fail_reasons.append(
            "queryEvents response did not contain a recognizable responseEnvelope/responseData "
            "structure, so the sweep/search capability could not be confirmed."
        )
        recommendations.append(
            "Confirm the Event Query API endpoint and credentials are correctly configured."
        )
        result = {
            "isThreatInvestigationSweepEnabled": False,
            "eventsReturned": 0,
        }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "eventsReturned": events_returned,
            "totalRecordsNumber": total_records,
        },
        api_errors=api_errors,
        metadata={
            "transformationId": "isThreatInvestigationSweepEnabled",
            "vendor": "Check Point Software Technologies Email Security",
            "category": "emailsecurity",
        },
    )
