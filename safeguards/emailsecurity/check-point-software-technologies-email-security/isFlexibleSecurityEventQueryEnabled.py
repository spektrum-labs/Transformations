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

    response_envelope = data.get("responseEnvelope")
    response_data = data.get("responseData")

    is_flexible_query_enabled = False

    if is_error:
        api_errors.append(
            f"queryEvents call returned error=true, errorType={error_type}, statusCode={status_code}: {data.get('message', data.get('errorMessage', 'unknown error'))}"
        )
        fail_reasons.append(
            f"queryEvents (POST /app/hec-api/v1.0/event/query) returned an authentication/API error (statusCode={status_code}, errorType={error_type}), so the flexible multi-criteria query capability could not be positively confirmed from this response."
        )
        recommendations.append(
            "Verify the clientId/accessKey credentials used for the Check Point Harmony Email Security integration and re-run the scan so a successful POST /event/query response with responseEnvelope/responseData can be captured."
        )
        is_flexible_query_enabled = False
    else:
        has_envelope_shape = isinstance(response_envelope, dict) or isinstance(response_data, list)
        if has_envelope_shape:
            is_flexible_query_enabled = True
            total_records = None
            if isinstance(response_envelope, dict):
                total_records = response_envelope.get("totalRecordsNumber")
            item_count = len(response_data) if isinstance(response_data, list) else 0
            pass_reasons.append(
                f"queryEvents (POST /app/hec-api/v1.0/event/query) returned a structured responseEnvelope/responseData shape "
                f"(totalRecordsNumber={total_records}, {item_count} events in this page), confirming the endpoint supports "
                "flexible multi-criteria POST queries (eventTypes, eventStates, severities, saas, confidenceIndicator, date range) "
                "rather than only fixed fetch-by-ID lookups."
            )
        else:
            fail_reasons.append(
                "queryEvents response did not contain the expected responseEnvelope/responseData keys, so flexible query "
                "capability could not be confirmed from this response body."
            )
            recommendations.append(
                "Re-run the scan against a tenant/credential set that can successfully call POST /app/hec-api/v1.0/event/query "
                "and inspect the resulting responseEnvelope/responseData structure."
            )
            is_flexible_query_enabled = False

    result = {
        "isFlexibleSecurityEventQueryEnabled": is_flexible_query_enabled,
    }

    input_summary = {
        "error": is_error,
        "statusCode": status_code,
        "hasResponseEnvelope": isinstance(response_envelope, dict),
        "hasResponseData": isinstance(response_data, list),
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
            "transformationId": "isFlexibleSecurityEventQueryEnabled",
            "vendor": "Check Point Software Technologies Email Security",
            "category": "Email Security",
        },
    )
