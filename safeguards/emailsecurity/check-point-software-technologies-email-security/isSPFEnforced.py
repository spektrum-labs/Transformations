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
    if data.get("error") is True or data.get("statusCode") == 401 or data.get("status") == "Error":
        msg = data.get("errorMessage") or data.get("message") or "Unknown API error"
        api_errors.append(f"Vendor API returned an error: {msg}")

    event = data.get("responseData")
    if isinstance(event, list):
        event = event[0] if event else {}
    if not isinstance(event, dict):
        event = {}

    event_data = event.get("data") or {}
    if not isinstance(event_data, dict):
        event_data = {}
    additional_data = event.get("additionalData") or {}
    if not isinstance(additional_data, dict):
        additional_data = {}

    spf_keys = ["spf", "spfCheckResult", "SPF", "spf_check_result", "spfResult"]
    spf_value = None
    found_source = None
    found_key = None
    for source_name, source in [("data", event_data), ("additionalData", additional_data), ("event", event)]:
        for key in spf_keys:
            if key in source and source.get(key) is not None:
                spf_value = source.get(key)
                found_source = source_name
                found_key = key
                break
        if spf_value is not None:
            break

    is_spf_enforced = False
    if spf_value is not None:
        if isinstance(spf_value, bool):
            is_spf_enforced = spf_value
        elif isinstance(spf_value, str):
            is_spf_enforced = spf_value.strip().lower() in ("pass", "true", "enforced", "yes")

    input_summary = {
        "eventId": event.get("eventId"),
        "spfFieldFound": found_key,
        "spfFieldSource": found_source,
        "spfValue": spf_value,
    }

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if api_errors:
        fail_reasons.append("Unable to determine SPF enforcement because the vendor API call failed authentication; no event data was returned.")
        recommendations.append("Verify the Check Point API credentials (clientId/accessKey) have permission to read events via /app/hec-api/v1.0/event/{eventId}, then re-run the check.")
    elif spf_value is None:
        fail_reasons.append("No SPF check result field (spf/spfCheckResult) was present in the event data or additionalData sections of the retrieved event.")
        recommendations.append("Confirm the queried event corresponds to an inbound/outbound mail event that carries authentication-result fields, or select an event with a documented SPF field.")
    elif is_spf_enforced:
        pass_reasons.append(f"Event field '{found_key}' found in '{found_source}' reports SPF value '{spf_value}', indicating SPF is being enforced/checked on outbound mail flow for this event.")
    else:
        fail_reasons.append(f"Event field '{found_key}' found in '{found_source}' reports SPF value '{spf_value}', indicating SPF did not pass or is not enforced for this event.")
        recommendations.append("Add or correct the SPF include record for the protected domain so outbound mail passes SPF validation under Check Point's deployment.")

    result = {
        "isSPFEnforced": is_spf_enforced,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isSPFEnforced",
            "vendor": "Check Point Software Technologies Email Security",
            "category": "emailsecurity",
        },
        api_errors=api_errors,
    )
