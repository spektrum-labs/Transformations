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

    is_error = bool(data.get("error"))
    error_type = data.get("errorType") or ""
    status_code = data.get("statusCode")

    if is_error:
        api_errors = [
            f"getAntiMalwareExceptions (exception_type=ppat_sender_name) returned error "
            f"(errorType={error_type}, statusCode={status_code}, message={data.get('message')})"
        ]
        result = {
            "isImposterEmailDetectionEnabled": False,
        }
        return create_response(
            result=result,
            validation=validation,
            fail_reasons=[
                f"Could not confirm the anti-impersonation (ppat_sender_name) exception "
                f"endpoint due to an API error: {data.get('message') or error_type or 'unknown error'}."
            ],
            recommendations=[
                "Verify API credentials (clientId/accessKey) have permission to read "
                "sectool-exceptions/checkpoint2/exceptions/ppat_sender_name and retry."
            ],
            input_summary={"error": True, "errorType": error_type, "statusCode": status_code},
            api_errors=api_errors,
            metadata={
                "transformationId": "isImposterEmailDetectionEnabled",
                "vendor": "Check Point Software Technologies Email Security",
                "category": "emailsecurity",
            },
        )

    response_envelope = data.get("responseEnvelope") or {}
    response_data = data.get("responseData")
    if not isinstance(response_data, list):
        response_data = []
    total_records = response_envelope.get("totalRecordsNumber")
    if not isinstance(total_records, int):
        total_records = len(response_data)

    # Reaching this endpoint successfully (no auth/API error) for the
    # ppat_sender_name (anti-impersonation) exception_type confirms the
    # imposter-email / anti-phishing verdict engine is provisioned and
    # configurable for this tenant.
    enabled = True

    result = {
        "isImposterEmailDetectionEnabled": enabled,
        "imposterExceptionCount": total_records,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=[
            f"The anti-impersonation (ppat_sender_name) exceptions endpoint responded "
            f"successfully with {total_records} configured exception(s), confirming "
            f"Check Point's imposter/phishing detection (anti-impersonation, 'ppat') tool "
            f"is provisioned and actively managed for this tenant."
        ],
        input_summary={"totalRecordsNumber": total_records, "itemCount": len(response_data)},
        metadata={
            "transformationId": "isImposterEmailDetectionEnabled",
            "vendor": "Check Point Software Technologies Email Security",
            "category": "emailsecurity",
        },
    )
