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
    if data.get("error") is True or data.get("statusCode") == 401 or data.get("status") == "Error":
        api_errors.append(
            "queryEvents returned an authentication/API error: %s"
            % (data.get("errorMessage") or data.get("message") or "unknown error")
        )

    items = data.get("responseData") or []
    if not isinstance(items, list):
        items = []

    move_action_types = ["quarantine", "restore", "delete", "dismiss", "remediation"]

    total_events = len(items)
    events_with_actions = 0
    move_related_events = 0
    move_related_with_trail = 0

    for item in items:
        if not isinstance(item, dict):
            continue
        actions = item.get("actions")
        available_actions = item.get("availableEventActions")
        has_trail = isinstance(actions, list) and len(actions) > 0
        if has_trail:
            events_with_actions = events_with_actions + 1

        event_type = str(item.get("type") or "").lower()
        description = str(item.get("description") or "").lower()
        is_move_related = False
        for kw in move_action_types:
            if kw in event_type or kw in description:
                is_move_related = True
                break
        if not is_move_related and isinstance(available_actions, list):
            for a in available_actions:
                a_str = str(a).lower()
                for kw in move_action_types:
                    if kw in a_str:
                        is_move_related = True
                        break
                if is_move_related:
                    break

        if is_move_related:
            move_related_events = move_related_events + 1
            if has_trail:
                move_related_with_trail = move_related_with_trail + 1

    input_summary = {
        "totalEvents": total_events,
        "eventsWithActionsArray": events_with_actions,
        "moveRelatedEvents": move_related_events,
        "moveRelatedEventsWithTrail": move_related_with_trail,
    }

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if api_errors:
        enabled = False
        fail_reasons.append(
            "Unable to confirm message-move audit trail: the queryEvents API call failed (%s), so no event 'actions' history could be inspected."
            % api_errors[0]
        )
        recommendations.append(
            "Verify API credentials (clientId/clientSecret) and re-run the /event/query call to confirm move-action events carry a populated 'actions' audit history array."
        )
    elif total_events == 0:
        enabled = False
        fail_reasons.append(
            "queryEvents returned zero events (responseData is empty), so no quarantine/restore/delete action history could be verified."
        )
        recommendations.append(
            "Broaden the /event/query filter criteria or confirm quarantine/restore/delete operations have occurred recently, then re-check that returned events include a non-empty 'actions' array."
        )
    elif move_related_events > 0 and move_related_with_trail == move_related_events:
        enabled = True
        pass_reasons.append(
            "All %d quarantine/restore/delete-related events out of %d total events returned by /event/query carry a non-empty 'actions' audit array, confirming every message-move action is logged with an auditable trail."
            % (move_related_with_trail, total_events)
        )
    elif move_related_events > 0 and move_related_with_trail > 0:
        enabled = False
        fail_reasons.append(
            "Only %d of %d quarantine/restore/delete-related events carry a populated 'actions' audit array; some move actions lack a recorded audit trail."
            % (move_related_with_trail, move_related_events)
        )
        recommendations.append(
            "Investigate why some quarantine/restore/delete events are missing populated 'actions' history and ensure the audit logging pipeline captures every move action."
        )
    elif move_related_events > 0 and move_related_with_trail == 0:
        enabled = False
        fail_reasons.append(
            "None of the %d quarantine/restore/delete-related events returned by /event/query carry a populated 'actions' audit array."
            % move_related_events
        )
        recommendations.append(
            "Confirm the audit-trail feature is enabled for message-move actions; escalate to Check Point support if 'actions' history is never populated."
        )
    else:
        enabled = events_with_actions > 0
        if enabled:
            pass_reasons.append(
                "No explicit quarantine/restore/delete-typed events were found in this query window, but %d of %d returned events carry a populated 'actions' audit array, evidencing the audit-trail mechanism is active."
                % (events_with_actions, total_events)
            )
        else:
            fail_reasons.append(
                "No quarantine/restore/delete-typed events were found and none of the %d returned events carry a populated 'actions' audit array."
                % total_events
            )
            recommendations.append(
                "Perform a quarantine/restore/delete action via the API and re-query to confirm the resulting event includes a populated 'actions' audit trail."
            )

    result = {
        "messageMoveAuditTrailEnabled": enabled,
        "totalEvents": total_events,
        "moveRelatedEvents": move_related_events,
        "moveRelatedEventsWithTrail": move_related_with_trail,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "messageMoveAuditTrailEnabled",
            "vendor": "Check Point Software Technologies Email Security",
            "category": "emailsecurity",
        },
        api_errors=api_errors,
    )
