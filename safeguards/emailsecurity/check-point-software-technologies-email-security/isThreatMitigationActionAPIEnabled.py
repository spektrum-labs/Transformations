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

    is_enabled = False
    task_id = None
    event_id = None

    is_error_flag = bool(data.get("error"))
    status_code = data.get("statusCode")
    error_type = data.get("errorType")

    response_data = data.get("responseData")
    response_data = response_data if isinstance(response_data, dict) else {}

    if is_error_flag or (isinstance(status_code, int) and status_code >= 400):
        if error_type == "authentication" or status_code == 401:
            # Endpoint exists and is reachable; failure is credential-related, not
            # evidence the action API itself is absent. Treat this as inconclusive
            # for enablement, but do not claim it is enabled without a successful
            # invocation.
            fail_reasons.append(
                f"POST /action/event returned an authentication error (statusCode={status_code}, "
                f"errorType={error_type}); could not confirm the mitigation action API executed "
                "successfully against this tenant."
            )
            recommendations.append(
                "Verify the clientId/accessKey credentials configured for this integration have "
                "permission to call the Harmony Email and Collaboration Action API, then re-run "
                "the scan."
            )
        else:
            fail_reasons.append(
                f"POST /action/event returned an error response (statusCode={status_code}, "
                f"errorType={error_type}, message={data.get('message')})."
            )
            recommendations.append(
                "Confirm the Threat Mitigation Action API is reachable and the request payload "
                "(eventIds, eventActionName) matches the documented schema."
            )
        is_enabled = False
    else:
        task_id = response_data.get("taskId")
        event_id = response_data.get("eventId")
        if task_id or event_id:
            is_enabled = True
            pass_reasons.append(
                f"POST /action/event was accepted and returned taskId={task_id}, eventId={event_id}, "
                "confirming a remediation action can be triggered programmatically on flagged messages."
            )
        else:
            fail_reasons.append(
                "POST /action/event returned a 200-shaped envelope but responseData contained no "
                "taskId/eventId, so the mitigation action could not be confirmed as accepted."
            )
            recommendations.append(
                "Inspect the raw response payload for responseEnvelope error details and confirm "
                "the eventIds/eventActionName fields sent in the request are valid."
            )

    input_summary = {
        "error": is_error_flag,
        "statusCode": status_code,
        "errorType": error_type,
        "taskId": task_id,
        "eventId": event_id,
    }

    return create_response(
        result={"isThreatMitigationActionAPIEnabled": is_enabled},
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isThreatMitigationActionAPIEnabled",
            "vendor": "Check Point Software Technologies Email Security",
            "category": "Email Security",
        },
        api_errors=api_errors,
    )
