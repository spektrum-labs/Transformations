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

    raw_response_envelope = data.get("responseEnvelope")
    raw_response_data = data.get("responseData")
    response_envelope = raw_response_envelope if isinstance(raw_response_envelope, dict) else {}
    response_data = raw_response_data if isinstance(raw_response_data, list) else []
    total_records = response_envelope.get("totalRecordsNumber")
    if not isinstance(total_records, int):
        total_records = len(response_data)

    # EVIDENCE REQUIRED: a recognised Check Point HEC envelope must actually be present.
    # `enabled` used to be hardcoded True on the reasoning that "reaching this endpoint
    # successfully confirms the tool is provisioned" -- but a body that never reached the
    # endpoint at all looks identical: {}, "{}", null and an unrelated payload such as
    # {"hello": "world"} carry no `error` key either, and all four reported imposter-email
    # detection as enabled. The getAntiMalwareExceptions (exception_type=ppat_sender_name)
    # response must carry a responseData list or a responseEnvelope object.
    enabled = isinstance(raw_response_data, list) or isinstance(raw_response_envelope, dict)

    if not enabled:
        return create_response(
            result={
                "isImposterEmailDetectionEnabled": False,
                "imposterExceptionCount": 0,
            },
            validation=validation,
            fail_reasons=[
                "The payload carried neither a responseData list nor a responseEnvelope object, so it is not a recognisable ppat_sender_name exceptions response and anti-impersonation (imposter email) detection could not be confirmed."
            ],
            recommendations=[
                "Confirm the integration is calling sectool-exceptions/checkpoint2/exceptions/ppat_sender_name and that the credentials return the documented responseEnvelope/responseData payload, then re-run this check."
            ],
            input_summary={"hasRecognizedEnvelope": False},
            metadata={
                "transformationId": "isImposterEmailDetectionEnabled",
                "vendor": "Check Point Software Technologies Email Security",
                "category": "emailsecurity",
            },
        )

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
