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
    if not isinstance(data, dict):
        data = {}

    api_errors = []

    # Handle vendor-level auth/API errors up front
    if data.get("error") or data.get("errorType") or data.get("statusCode") == 401:
        err_msg = data.get("errorMessage") or data.get("message") or "Unknown API error"
        api_errors.append(f"queryEvents API error: {err_msg}")
        return create_response(
            result={"isShadowITDiscoveryEnabled": False},
            validation=validation,
            fail_reasons=[
                f"queryEvents call failed ({err_msg}); could not confirm Shadow IT discovery events were returned."
            ],
            recommendations=[
                "Verify the Check Point Harmony Email API credentials (clientId/accessKey) are valid and re-run the query."
            ],
            input_summary={"apiError": err_msg},
            api_errors=api_errors,
        )

    response_data = data.get("responseData") or []
    if not isinstance(response_data, list):
        response_data = []

    shadow_it_keywords = ["shadow_it", "shadow-it", "shadowit", "shadow it", "unsanctioned", "unauthorized_app"]

    shadow_it_events = []
    for e in response_data:
        if not isinstance(e, dict):
            continue
        type_val = str(e.get("type") or "").lower()
        desc_val = str(e.get("description") or "").lower()
        matched = False
        for kw in shadow_it_keywords:
            if kw in type_val or kw in desc_val:
                matched = True
                break
        if matched:
            shadow_it_events.append(e)

    verdicted_events = [
        e for e in shadow_it_events
        if e.get("confidenceIndicator") or e.get("state") or e.get("severity")
    ]

    total_events = len(response_data)
    shadow_it_count = len(shadow_it_events)
    verdicted_count = len(verdicted_events)

    is_enabled = shadow_it_count > 0 and verdicted_count > 0

    input_summary = {
        "totalEventsReturned": total_events,
        "shadowITEvents": shadow_it_count,
        "verdictedShadowITEvents": verdicted_count,
    }

    if is_enabled:
        sample = verdicted_events[0]
        pass_reasons = [
            f"queryEvents returned {shadow_it_count} Shadow IT / unsanctioned-app event(s) out of {total_events} total events, "
            f"and {verdicted_count} of them carry a verdict (e.g. eventId={sample.get('eventId')}, "
            f"type={sample.get('type')}, confidenceIndicator={sample.get('confidenceIndicator')}, state={sample.get('state')})."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        if total_events == 0:
            fail_reasons = [
                "queryEvents returned zero events in this response, so no Shadow IT / unsanctioned-app discoveries could be confirmed."
            ]
        else:
            fail_reasons = [
                f"queryEvents returned {total_events} events but none matched Shadow IT / unsanctioned-app type or description patterns, "
                "or none of the matches carried a verdict (confidenceIndicator/state/severity)."
            ]
        recommendations = [
            "Enable and configure Shadow IT / unsanctioned SaaS app discovery in the Harmony Email and Collaboration policy, "
            "then re-run the event query to confirm verdicted Shadow IT events are generated."
        ]

    return create_response(
        result={
            "isShadowITDiscoveryEnabled": is_enabled,
            "shadowITEventsFound": shadow_it_count,
            "verdictedShadowITEvents": verdicted_count,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isShadowITDiscoveryEnabled",
            "vendor": "Check Point Software Technologies Email Security",
            "category": "emailsecurity",
        },
    )
