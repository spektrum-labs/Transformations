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
    pass_reasons = []
    fail_reasons = []
    recommendations = []

    is_error = bool(data.get("error")) or data.get("status") == "Error" or data.get("statusCode") == 401

    if is_error:
        api_errors.append(str(data.get("errorMessage") or data.get("message") or "Unknown error from queryEvents"))
        is_logging_enabled = False
        fail_reasons.append(
            "queryEvents returned an error (errorType=%s, statusCode=%s, message=%s); unable to confirm email security event logging is active."
            % (str(data.get("errorType")), str(data.get("statusCode")), str(data.get("errorMessage") or data.get("message")))
        )
        recommendations.append(
            "Verify the clientId/clientSecret credentials configured for the Check Point Harmony Email Security integration and re-authenticate so that /event/query can retrieve security event telemetry."
        )
        input_summary = {"error": True, "statusCode": data.get("statusCode")}

        return create_response(
            result={"isEmailSecurityLoggingEnabled": is_logging_enabled},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary=input_summary,
            api_errors=api_errors,
            metadata={
                "transformationId": "isEmailSecurityLoggingEnabled",
                "vendor": "Check Point Software Technologies Email Security",
                "category": "emailsecurity",
            },
        )

    events = data.get("responseData") or []
    if not isinstance(events, list):
        events = []
    total_events = len(events)

    fields_present = 0
    for ev in events:
        if isinstance(ev, dict) and ev.get("eventId") and ev.get("eventTypes"):
            fields_present = fields_present + 1

    is_logging_enabled = total_events > 0

    if is_logging_enabled:
        pass_reasons.append(
            "queryEvents (/event/query) returned %d security event record(s), of which %d carry populated eventId/eventTypes fields, indicating the email security event logging pipeline is actively capturing threat detections, actions taken, and policy violations."
            % (total_events, fields_present)
        )
    else:
        fail_reasons.append(
            "queryEvents (/event/query) returned zero records in responseData for the queried window, so no evidence of active email security event logging (threats detected, actions taken, policy violations) could be confirmed."
        )
        recommendations.append(
            "Confirm the Harmony Email and Collaboration event logging pipeline is enabled and that the queried time window/filters actually include recent mail traffic; re-run /event/query with a broader lookback."
        )

    input_summary = {"totalEvents": total_events, "eventsWithCoreFields": fields_present}

    return create_response(
        result={"isEmailSecurityLoggingEnabled": is_logging_enabled, "totalEvents": total_events},
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isEmailSecurityLoggingEnabled",
            "vendor": "Check Point Software Technologies Email Security",
            "category": "emailsecurity",
        },
    )
