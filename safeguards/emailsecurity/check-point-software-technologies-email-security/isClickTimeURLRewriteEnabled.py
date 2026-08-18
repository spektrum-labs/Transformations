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
    status_code = data.get("statusCode")
    error_type = data.get("errorType")
    error_message = data.get("errorMessage") or data.get("message")

    if is_error:
        api_errors = [f"Click-Time Protection exceptions endpoint returned error: {error_type} - {error_message} (statusCode={status_code})"]
        result = {
            "isClickTimeURLRewriteEnabled": False,
            "exceptionCount": 0,
        }
        return create_response(
            result=result,
            validation=validation,
            fail_reasons=[
                f"Could not confirm Click-Time URL Rewrite is active: the dedicated /sectools/click_time_protection/exceptions endpoint returned an error ({error_type}, statusCode={status_code}, message='{error_message}') rather than a successful exceptions list."
            ],
            recommendations=[
                "Verify the API credentials (clientId/accessKey) have permission to call the click_time_protection exceptions endpoint, then re-run this check to confirm Click-Time URL Rewrite status."
            ],
            input_summary={"error": True, "statusCode": status_code, "errorType": error_type},
            api_errors=api_errors,
            metadata={
                "transformationId": "isClickTimeURLRewriteEnabled",
                "vendor": "Check Point Software Technologies Email Security",
                "category": "Email Security",
            },
        )

    response_data = data.get("responseData")
    if not isinstance(response_data, list):
        response_data = []
    response_envelope = data.get("responseEnvelope")
    if not isinstance(response_envelope, dict):
        response_envelope = {}

    exception_count = len(response_data)
    total_records = response_envelope.get("totalRecordsNumber")
    if not isinstance(total_records, int):
        total_records = exception_count

    result = {
        "isClickTimeURLRewriteEnabled": True,
        "exceptionCount": total_records,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=[
            f"The dedicated Click-Time Protection exceptions endpoint (/sectools/click_time_protection/exceptions) responded successfully with a responseData list of {exception_count} exception entries (responseEnvelope.totalRecordsNumber={total_records}), confirming the Click-Time URL Rewrite protection tool is provisioned and manageable via API."
        ],
        input_summary={"exceptionCount": exception_count, "totalRecordsNumber": total_records},
        metadata={
            "transformationId": "isClickTimeURLRewriteEnabled",
            "vendor": "Check Point Software Technologies Email Security",
            "category": "Email Security",
        },
    )
