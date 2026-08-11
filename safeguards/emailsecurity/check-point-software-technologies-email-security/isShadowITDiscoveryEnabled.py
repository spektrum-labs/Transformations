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
    if data.get("error") or data.get("statusCode") == 401:
        api_errors.append(str(data.get("errorMessage") or data.get("message") or "API error"))

    items = data.get("responseData") or data.get("data") or []
    if not isinstance(items, list):
        items = []

    envelope = data.get("responseEnvelope") or {}
    total_records = envelope.get("totalRecordsNumber") if isinstance(envelope, dict) else None

    shadow_it_events = []
    for ev in items:
        if not isinstance(ev, dict):
            continue
        ev_type = str(ev.get("type") or "")
        ev_desc = str(ev.get("description") or "")
        if "shadow it" in ev_type.lower() or "shadow it" in ev_desc.lower():
            shadow_it_events.append(ev)

    shadow_it_count = len(shadow_it_events)
    is_enabled = shadow_it_count > 0

    input_summary = {
        "totalEventsInPage": len(items),
        "shadowITEventsFound": shadow_it_count,
        "totalRecordsNumber": total_records,
    }

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_enabled:
        sample = shadow_it_events[0]
        pass_reasons.append(
            f"Found {shadow_it_count} Shadow IT event(s) in queried events, e.g. eventId={sample.get('eventId')} "
            f"type={sample.get('type')} description={sample.get('description')!r}, confirming Shadow IT discovery "
            f"detection is active and producing verdicted events."
        )
    else:
        if api_errors:
            fail_reasons.append(
                f"queryEvents call did not return usable event data (errors: {api_errors}); "
                f"could not confirm Shadow IT discovery events."
            )
            recommendations.append(
                "Verify API credentials/authentication for the Check Point Email Security integration and re-run the scan."
            )
        else:
            fail_reasons.append(
                f"No events with type or description containing 'Shadow IT' were found among {len(items)} "
                f"queried events (totalRecordsNumber={total_records})."
            )
            recommendations.append(
                "Confirm the Shadow IT discovery engine is enabled in the Check Point Harmony Email and "
                "Collaboration console and that SaaS app connections are being scanned."
            )

    result = {
        "isShadowITDiscoveryEnabled": is_enabled,
        "shadowITEventsFound": shadow_it_count,
        "totalEventsInPage": len(items),
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
            "transformationId": "isShadowITDiscoveryEnabled",
            "vendor": "Check Point Software Technologies Email Security",
            "category": "emailsecurity",
        },
    )
