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
    # Detect an explicit vendor error envelope (e.g. authentication failure)
    if data.get("error") is True or data.get("statusCode") == 401 or data.get("status") == "Error":
        api_errors.append(
            "Vendor API returned error: %s (statusCode=%s)"
            % (str(data.get("errorMessage") or data.get("message") or "unknown error"),
               str(data.get("statusCode") or "unknown"))
        )

    items = data.get("responseData") or []
    if not isinstance(items, list):
        items = []

    o365_events = []
    for e in items:
        if not isinstance(e, dict):
            continue
        saas_value = str(e.get("saas") or "").lower()
        if "office365" in saas_value or "o365" in saas_value:
            o365_events.append(e)

    total_events = len(items)
    o365_count = len(o365_events)
    is_linked_active = o365_count > 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_linked_active:
        sample_ids = [str(e.get("eventId")) for e in o365_events[:5]]
        pass_reasons.append(
            "Found %d event(s) with saas indicating Office 365 (e.g. eventId(s): %s) out of %d total events queried, confirming an actively linked and streaming O365 tenant."
            % (o365_count, ", ".join(sample_ids) if sample_ids else "n/a", total_events)
        )
    else:
        if api_errors:
            fail_reasons.append(
                "Could not confirm an active O365 link: the /event/query call returned an error (%s) instead of event data."
                % (api_errors[0])
            )
            recommendations.append(
                "Verify the API client credentials (clientId/clientSecret) have valid scopes and re-run the query against /event/query to confirm the O365 tenant is streaming events."
            )
        else:
            fail_reasons.append(
                "Queried %d event(s) from /event/query and found none with a saas field referencing office365, indicating the linked O365 account may not be actively streaming entities."
                % total_events
            )
            recommendations.append(
                "Confirm the Office 365 tenant link is still authorized in the Check Point Infinity Portal and that recent mail traffic is being ingested."
            )

    result = {
        "isLinkedO365AccountActive": is_linked_active,
        "totalEventsQueried": total_events,
        "o365EventCount": o365_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalEventsQueried": total_events, "o365EventCount": o365_count},
        metadata={
            "transformationId": "isLinkedO365AccountActive",
            "vendor": "Check Point Software Technologies Email Security",
            "category": "emailsecurity",
        },
        api_errors=api_errors,
    )
