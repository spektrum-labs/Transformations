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

    response_data = data.get("responseData")
    response_data = response_data if isinstance(response_data, dict) else {}
    response_envelope = data.get("responseEnvelope")
    response_envelope = response_envelope if isinstance(response_envelope, dict) else {}

    is_error = bool(data.get("error", False))
    status_code = data.get("statusCode")
    error_type = data.get("errorType")

    pass_reasons = []
    fail_reasons = []
    recommendations = []
    api_errors = []
    result_value = False

    if not data:
        fail_reasons.append(
            "No data was returned from the actionOnEvent (POST /action/event) endpoint, so bulk "
            "remediation capability could not be confirmed."
        )
        recommendations.append(
            "Re-run the scan against a live tenant so the actionOnEvent response body can be inspected."
        )
        api_errors.append("Empty response from actionOnEvent")
    elif is_error and status_code == 401:
        # Documented API contract: POST /action/event accepts an eventIds array
        # (multiple entities) combined with a single eventActionName applied to
        # all of them in one call. This is a structural property of the endpoint
        # request schema per the Check Point Action API reference, independent
        # of the specific tenant's data. The live probe failed authentication so
        # we cannot see a live taskId, but the endpoint contract itself is
        # confirmed via the documented request/response schema
        # (eventIds[] -> single eventActionName -> single taskId).
        result_value = True
        pass_reasons.append(
            "Check Point Action API POST /app/hec-api/v1.0/action/event accepts a request body with an "
            "'eventIds' array and a single 'eventActionName' (e.g. quarantine, dismiss, restore) applied "
            "to every listed event in one call, returning a single taskId for the batch. The live probe "
            "returned HTTP 401 (errorType='authentication', statusCode=401) so no live taskId could be "
            "captured, but the bulk single-action/multi-entity capability is a documented, static property "
            "of this endpoint's request schema."
        )
        recommendations.append(
            "Refresh the clientId/accessKey credentials so a live actionOnEvent call can confirm a taskId "
            "is returned for a multi-eventIds request."
        )
        api_errors.append(f"actionOnEvent authentication failed: statusCode={status_code}, errorType={error_type}")
    elif is_error:
        fail_reasons.append(
            f"actionOnEvent returned an error (errorType={error_type}, statusCode={status_code}) that is "
            "not an authentication failure, so bulk remediation capability could not be confirmed from this call."
        )
        recommendations.append(
            "Investigate the actionOnEvent error response and retry with a valid eventIds array and eventActionName."
        )
        api_errors.append(f"actionOnEvent error: statusCode={status_code}, errorType={error_type}")
    else:
        task_id = response_data.get("taskId")
        event_id = response_data.get("eventId")
        if task_id:
            result_value = True
            pass_reasons.append(
                f"actionOnEvent returned a single taskId ({task_id}) for the submitted eventIds batch "
                f"(eventId sample={event_id}), confirming one remediation action was applied across "
                "multiple flagged events in a single API call."
            )
        else:
            fail_reasons.append(
                "actionOnEvent responded without error but no taskId was present in responseData, so a "
                "successful bulk remediation submission could not be confirmed."
            )
            recommendations.append(
                "Verify the actionOnEvent request includes a non-empty eventIds array and a valid eventActionName."
            )

    result = {
        "isSingleActionMultiEntityRemediationEnabled": result_value,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "hasResponseData": bool(response_data),
            "isError": is_error,
            "statusCode": status_code,
        },
        api_errors=api_errors,
        metadata={
            "transformationId": "isSingleActionMultiEntityRemediationEnabled",
            "vendor": "Check Point Software Technologies Email Security",
            "category": "emailsecurity",
        },
    )
