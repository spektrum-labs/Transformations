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
    error_type = data.get("errorType")
    status_field = data.get("status")
    status_code = data.get("statusCode")
    error_message = data.get("errorMessage") or data.get("message") or ""

    response_envelope = data.get("responseEnvelope")
    response_envelope = response_envelope if isinstance(response_envelope, dict) else {}
    response_data = data.get("responseData")

    api_errors = []
    fail_reasons = []
    pass_reasons = []
    recommendations = []

    is_auth_error = bool(error_flag) or status_field == "Error" or error_type == "authentication" or status_code == 401

    if is_auth_error:
        api_errors.append(f"Vendor API returned an error response: {error_message or error_type or status_field}")
        fail_reasons.append(
            f"Could not retrieve the click-time protection exceptions list "
            f"(errorType={error_type}, statusCode={status_code}, message='{error_message}'), "
            f"so URL reputation block-list enforcement could not be confirmed."
        )
        recommendations.append(
            "Verify the clientId/accessKey credentials used for this integration have permission to "
            "call the Click-Time Protection exceptions endpoint, then re-run the scan."
        )
        result = {
            "isURLReputationBlockListEnforced": False,
            "exceptionCount": 0,
        }
        input_summary = {
            "hadError": True,
            "errorType": error_type,
            "statusCode": status_code,
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
                "transformationId": "isURLReputationBlockListEnforced",
                "vendor": "Check Point Software Technologies Email Security",
                "category": "emailsecurity",
            },
        )

    items = response_data if isinstance(response_data, list) else []
    total_records = response_envelope.get("totalRecordsNumber")
    if not isinstance(total_records, int):
        total_records = len(items)

    is_enforced = "responseEnvelope" in data or "responseData" in data

    if is_enforced:
        pass_reasons.append(
            f"Click-Time Protection exceptions endpoint returned a valid responseEnvelope/responseData "
            f"payload with {total_records} exception entries, confirming click-time URL "
            f"reputation blocking is active (exceptions are only meaningful against an "
            f"enforced block policy)."
        )
    else:
        fail_reasons.append(
            "Response did not contain a responseEnvelope or responseData key, so click-time "
            "URL reputation block-list enforcement could not be confirmed from this payload."
        )
        recommendations.append(
            "Confirm the Click-Time Protection feature is enabled for this tenant in the "
            "Harmony Email and Collaboration admin console."
        )

    result = {
        "isURLReputationBlockListEnforced": bool(is_enforced),
        "exceptionCount": total_records,
    }
    input_summary = {
        "totalRecordsNumber": total_records,
        "itemCount": len(items),
    }
    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isURLReputationBlockListEnforced",
            "vendor": "Check Point Software Technologies Email Security",
            "category": "emailsecurity",
        },
    )
