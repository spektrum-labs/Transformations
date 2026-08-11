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

    error_flag = data.get("error")
    status_code = data.get("statusCode")
    error_message = data.get("errorMessage") or data.get("message")

    response_envelope = data.get("responseEnvelope")
    if not isinstance(response_envelope, dict):
        response_envelope = {}

    response_data = data.get("responseData")
    if response_data is None:
        response_data = data.get("data")
    if not isinstance(response_data, list):
        response_data = []

    total_records = response_envelope.get("totalRecordsNumber") if isinstance(response_envelope, dict) else None

    api_errors = []
    if error_flag:
        api_errors.append(f"API error: {error_message or 'unknown error'} (statusCode={status_code})")

    if error_flag:
        is_enabled = False
        fail_reasons = [
            f"queryEvents endpoint (POST /event/query) returned an error ({error_message or 'unknown'}, statusCode={status_code}), so the flexible multi-criteria event query capability could not be confirmed for this tenant."
        ]
        pass_reasons = []
        recommendations = [
            "Verify Check Point Harmony Email Security OAuth credentials (clientId/clientSecret) and re-run queryEvents with a valid access token to confirm POST /event/query flexible query support."
        ]
    else:
        has_envelope_key = "responseEnvelope" in data or "responseData" in data
        has_envelope_content = isinstance(response_envelope, dict) and len(response_envelope) > 0
        if has_envelope_key or has_envelope_content:
            is_enabled = True
            pass_reasons = [
                f"POST /event/query (queryEvents) responded successfully with the documented responseEnvelope/responseData structure (totalRecordsNumber={total_records}, {len(response_data)} record(s) in this page), confirming the flexible, multi-criteria POST query endpoint is reachable and functional, distinct from the fixed getEventById lookup-by-ID endpoint."
            ]
            fail_reasons = []
            recommendations = []
        else:
            is_enabled = False
            pass_reasons = []
            fail_reasons = [
                "queryEvents response did not contain the expected responseEnvelope/responseData structure, so the flexible multi-criteria query capability could not be confirmed from this response."
            ]
            recommendations = [
                "Confirm connectivity and authentication to POST /event/query and inspect the returned response shape for responseEnvelope/responseData."
            ]

    result = {
        "isFlexibleSecurityEventQueryEnabled": is_enabled,
        "totalRecords": total_records if total_records is not None else len(response_data),
    }

    input_summary = {
        "hasError": bool(error_flag),
        "statusCode": status_code,
        "responseDataCount": len(response_data),
        "totalRecordsNumber": total_records,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isFlexibleSecurityEventQueryEnabled",
            "vendor": "Check Point Software Technologies Email Security",
            "category": "emailsecurity",
        },
        api_errors=api_errors,
    )
