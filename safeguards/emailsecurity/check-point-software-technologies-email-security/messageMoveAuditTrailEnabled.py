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


MOVE_ACTION_KEYWORDS = ["quarantine", "restore", "delete", "remove", "move", "unquarantine"]


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, dict) else {}

    api_errors = []
    if data.get("error") is True or data.get("errorType") == "authentication":
        api_errors.append(str(data.get("errorMessage") or data.get("message") or "API error"))

    events = data.get("responseData") or []
    if not isinstance(events, list):
        events = []

    total_events = len(events)
    events_with_move_actions = 0
    audited_move_actions = 0
    total_move_actions = 0
    sample_findings = []

    for ev in events:
        if not isinstance(ev, dict):
            continue
        actions = ev.get("actions") or []
        if not isinstance(actions, list):
            actions = []
        event_has_move_action = False
        for act in actions:
            if not isinstance(act, dict):
                continue
            action_type = str(act.get("actionType") or act.get("type") or "").lower()
            is_move_action = False
            for kw in MOVE_ACTION_KEYWORDS:
                if kw in action_type:
                    is_move_action = True
                    break
            if is_move_action:
                total_move_actions = total_move_actions + 1
                event_has_move_action = True
                has_audit_fields = bool(act.get("createTime")) and bool(act.get("actionType") or act.get("type"))
                if has_audit_fields:
                    audited_move_actions = audited_move_actions + 1
                    if len(sample_findings) < 3:
                        sample_findings.append(
                            f"eventId={ev.get('eventId')} actionType={action_type} createTime={act.get('createTime')}"
                        )
        if event_has_move_action:
            events_with_move_actions = events_with_move_actions + 1

    is_enabled = total_move_actions > 0 and audited_move_actions == total_move_actions

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if api_errors:
        fail_reasons.append(
            f"API call to queryEvents failed with error: {'; '.join(api_errors)}. Unable to verify audit trail."
        )
        recommendations.append(
            "Verify API credentials (clientId/accessKey) and re-run the event query to confirm audit logging of quarantine/restore/delete actions."
        )
    elif total_events == 0:
        fail_reasons.append(
            "queryEvents returned zero events in responseData; no message-move actions were available to verify an audit trail."
        )
        recommendations.append(
            "Perform a quarantine/restore/delete action via the API and re-query events to confirm the actions[] array records it with actionType and createTime."
        )
    elif total_move_actions == 0:
        fail_reasons.append(
            f"Scanned {total_events} events but found no quarantine/restore/delete actions in any actions[] array, so audit trail coverage could not be confirmed."
        )
        recommendations.append(
            "Confirm that message-move actions (quarantine, restore, delete) are being executed via the API and check that they populate the actions[] array."
        )
    elif is_enabled:
        pass_reasons.append(
            f"Found {total_move_actions} quarantine/restore/delete action(s) across {events_with_move_actions} of {total_events} events, "
            f"and all {audited_move_actions} carry both actionType and createTime fields forming a complete audit trail. Examples: "
            + "; ".join(sample_findings)
        )
    else:
        fail_reasons.append(
            f"Of {total_move_actions} quarantine/restore/delete action(s) found across {events_with_move_actions} events, only "
            f"{audited_move_actions} carry both actionType and createTime fields; the remainder are missing audit metadata."
        )
        recommendations.append(
            "Investigate events whose actions[] entries lack createTime or actionType to ensure every message-move action is fully audited."
        )

    input_summary = {
        "totalEvents": total_events,
        "eventsWithMoveActions": events_with_move_actions,
        "totalMoveActions": total_move_actions,
        "auditedMoveActions": audited_move_actions,
    }

    result = {
        "messageMoveAuditTrailEnabled": is_enabled,
        "totalMoveActions": total_move_actions,
        "auditedMoveActions": audited_move_actions,
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
            "transformationId": "messageMoveAuditTrailEnabled",
            "vendor": "Check Point Software Technologies Email Security",
            "category": "Email Security",
        },
    )
