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


# Actions that represent a retroactive, post-delivery quarantine capability.
QUARANTINE_ACTION_TOKENS = ["quarantine", "restore", "remediate"]
POST_DELIVERY_STATE_TOKENS = ["quarantined", "dismissed", "remediated"]


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, dict) else {}

    api_errors = []
    if data.get("error") or data.get("statusCode") == 401 or data.get("errorType") == "authentication":
        api_errors.append(str(data.get("errorMessage") or data.get("message") or "API error"))

    events = data.get("responseData") or []
    if not isinstance(events, list):
        events = []

    envelope = data.get("responseEnvelope") or {}
    total_records = envelope.get("totalRecordsNumber") if isinstance(envelope, dict) else None

    quarantine_capable_events = []
    post_delivery_malicious_events = []

    for ev in events:
        if not isinstance(ev, dict):
            continue
        state = str(ev.get("state") or "").lower()
        actions = ev.get("availableEventActions") or []
        if not isinstance(actions, list):
            actions = []
        actions_lower = [str(a).lower() for a in actions]

        is_post_delivery_state = any(tok in state for tok in POST_DELIVERY_STATE_TOKENS) or state == "malicious"
        has_quarantine_action = any(
            any(tok in a for tok in QUARANTINE_ACTION_TOKENS) for a in actions_lower
        )

        if is_post_delivery_state:
            post_delivery_malicious_events.append(ev.get("eventId"))
        if has_quarantine_action:
            quarantine_capable_events.append(ev.get("eventId"))

    total_events = len(events)
    is_enabled = len(quarantine_capable_events) > 0

    input_summary = {
        "totalEventsInPage": total_events,
        "totalRecordsNumber": total_records,
        "quarantineCapableEventCount": len(quarantine_capable_events),
        "postDeliveryStateEventCount": len(post_delivery_malicious_events),
    }

    if api_errors:
        return create_response(
            result={"isPostDeliveryQuarantineEnabled": False},
            validation=validation,
            fail_reasons=[
                f"queryEvents API call failed: {api_errors[0]}. Unable to confirm post-delivery quarantine capability."
            ],
            recommendations=[
                "Verify OAuth client credentials (clientId/clientSecret) have permission to call /event/query, then re-run this check."
            ],
            input_summary=input_summary,
            api_errors=api_errors,
            metadata={"transformationId": "isPostDeliveryQuarantineEnabled",
                      "vendor": "Check Point Software Technologies Email Security",
                      "category": "emailsecurity"},
        )

    if total_events == 0:
        return create_response(
            result={"isPostDeliveryQuarantineEnabled": False},
            validation=validation,
            fail_reasons=[
                "queryEvents returned no events in responseData; no evidence of a quarantine action being available on any event, so post-delivery quarantine capability could not be confirmed."
            ],
            recommendations=[
                "Run a broader /event/query (wider date range / no state filter) so at least one malicious/quarantined event with availableEventActions is returned."
            ],
            input_summary=input_summary,
            metadata={"transformationId": "isPostDeliveryQuarantineEnabled",
                      "vendor": "Check Point Software Technologies Email Security",
                      "category": "emailsecurity"},
        )

    if is_enabled:
        sample_ids = quarantine_capable_events[:5]
        pass_reasons = [
            f"{len(quarantine_capable_events)} of {total_events} events returned by /event/query expose a "
            f"quarantine/restore action in availableEventActions (sample eventIds: {sample_ids}), "
            f"confirming messages verdicted malicious after delivery can be retroactively quarantined via the API."
        ]
        return create_response(
            result={"isPostDeliveryQuarantineEnabled": True},
            validation=validation,
            pass_reasons=pass_reasons,
            input_summary=input_summary,
            metadata={"transformationId": "isPostDeliveryQuarantineEnabled",
                      "vendor": "Check Point Software Technologies Email Security",
                      "category": "emailsecurity"},
        )
    else:
        fail_reasons = [
            f"None of the {total_events} events returned by /event/query expose a quarantine/restore action in "
            f"availableEventActions ({len(post_delivery_malicious_events)} events were in a post-delivery state "
            f"such as quarantined/dismissed), so retroactive post-delivery quarantine could not be confirmed."
        ]
        return create_response(
            result={"isPostDeliveryQuarantineEnabled": False},
            validation=validation,
            fail_reasons=fail_reasons,
            recommendations=[
                "Confirm that the HEC quarantine policy is enabled and that the API client has permission to see "
                "availableEventActions containing a restore/quarantine action on malicious post-delivery events."
            ],
            input_summary=input_summary,
            metadata={"transformationId": "isPostDeliveryQuarantineEnabled",
                      "vendor": "Check Point Software Technologies Email Security",
                      "category": "emailsecurity"},
        )
