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
        error_msg = data.get("errorMessage") or data.get("message") or "Unknown API error"
        api_errors.append(f"Vendor API error: {error_msg}")
        return create_response(
            result={"openQuarantinedMessagesCount": 0},
            validation=validation,
            fail_reasons=[f"Could not retrieve quarantine event data due to API error: {error_msg}"],
            recommendations=["Verify API credentials (clientId/clientSecret) have valid scope for event/query and retry."],
            input_summary={"apiError": error_msg},
            api_errors=api_errors,
            metadata={"transformationId": "openQuarantinedMessagesCount", "vendor": "Check Point Software Technologies Email Security", "category": "emailsecurity"},
        )

    envelope = data.get("responseEnvelope") or {}
    items = data.get("responseData") or []
    if not isinstance(items, list):
        items = []

    quarantined_in_page = 0
    for item in items:
        if not isinstance(item, dict):
            continue
        state = item.get("state")
        if isinstance(state, str) and state.lower() == "quarantined":
            quarantined_in_page = quarantined_in_page + 1

    total_records = envelope.get("totalRecordsNumber")

    if isinstance(total_records, int):
        count = total_records
        source_desc = f"responseEnvelope.totalRecordsNumber={total_records} (query filtered on state=quarantined)"
    else:
        count = quarantined_in_page
        source_desc = f"counted {quarantined_in_page} items with state='quarantined' in the returned page (no totalRecordsNumber present)"

    pass_reasons = []
    fail_reasons = []
    if count > 0:
        pass_reasons.append(f"Query for quarantined events returned {count} open quarantined messages ({source_desc}).")
    else:
        pass_reasons.append(f"Query for quarantined events returned 0 open quarantined messages ({source_desc}).")

    return create_response(
        result={"openQuarantinedMessagesCount": count},
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        input_summary={"totalRecordsNumber": total_records, "itemsInPage": len(items), "quarantinedInPage": quarantined_in_page},
        metadata={"transformationId": "openQuarantinedMessagesCount", "vendor": "Check Point Software Technologies Email Security", "category": "emailsecurity"},
    )
