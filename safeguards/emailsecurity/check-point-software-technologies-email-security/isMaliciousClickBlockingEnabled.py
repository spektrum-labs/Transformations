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


MALICIOUS_CLICK_TYPE_HINTS = [
    "malicious_url",
    "malicious url",
    "url_click",
    "click",
    "phishing_url",
]

BLOCK_ACTION_HINTS = [
    "block",
    "blocked",
    "quarantine",
    "quarantined",
]


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, dict) else {}

    api_errors = []
    if data.get("error") is True or data.get("errorType") == "authentication":
        api_errors.append(str(data.get("errorMessage") or data.get("message") or "API error"))

    events = data.get("responseData") or data.get("data") or []
    if not isinstance(events, list):
        events = []

    malicious_click_events = []
    for ev in events:
        if not isinstance(ev, dict):
            continue
        ev_type = str(ev.get("type") or "").lower()
        ev_desc = str(ev.get("description") or "").lower()
        is_click_related = False
        for hint in MALICIOUS_CLICK_TYPE_HINTS:
            if hint in ev_type or hint in ev_desc:
                is_click_related = True
                break
        confidence = str(ev.get("confidenceIndicator") or "").lower()
        if is_click_related and ("malicious" in ev_type or "malicious" in ev_desc or confidence == "malicious"):
            malicious_click_events.append(ev)

    blocked_count = 0
    unblocked_examples = []
    for ev in malicious_click_events:
        actions = ev.get("actions") or []
        if not isinstance(actions, list):
            actions = []
        state = str(ev.get("state") or "").lower()
        was_blocked = False
        if any(h in state for h in BLOCK_ACTION_HINTS):
            was_blocked = True
        for act in actions:
            if not isinstance(act, dict):
                continue
            action_type = str(act.get("actionType") or "").lower()
            if any(h in action_type for h in BLOCK_ACTION_HINTS):
                was_blocked = True
                break
        if was_blocked:
            blocked_count = blocked_count + 1
        else:
            if len(unblocked_examples) < 3:
                unblocked_examples.append(ev.get("eventId") or "unknown")

    total_malicious_click = len(malicious_click_events)

    input_summary = {
        "totalEventsReturned": len(events),
        "maliciousClickEvents": total_malicious_click,
        "blockedMaliciousClickEvents": blocked_count,
    }

    if api_errors:
        result = {"isMaliciousClickBlockingEnabled": False}
        return create_response(
            result=result,
            validation=validation,
            fail_reasons=["API call failed: " + "; ".join(api_errors)],
            recommendations=["Verify API credentials (clientId/accessKey) and retry the event query."],
            input_summary=input_summary,
            api_errors=api_errors,
            metadata={"transformationId": "isMaliciousClickBlockingEnabled", "vendor": "Check Point Software Technologies Email Security", "category": "emailsecurity"},
        )

    if total_malicious_click == 0:
        result = {"isMaliciousClickBlockingEnabled": False}
        return create_response(
            result=result,
            validation=validation,
            fail_reasons=["No malicious-URL click events were found in the queried event set (responseData had %d events, none matched malicious click-type/confidence criteria)." % len(events)],
            recommendations=["Confirm Click-Time Protection is enabled and query a broader time range or eventTypes filter including malicious URL click categories."],
            input_summary=input_summary,
            metadata={"transformationId": "isMaliciousClickBlockingEnabled", "vendor": "Check Point Software Technologies Email Security", "category": "emailsecurity"},
        )

    is_enabled = blocked_count == total_malicious_click and blocked_count > 0

    if is_enabled:
        pass_reasons = [
            "All %d malicious-click events (confidenceIndicator=malicious, click-type events) show a block/quarantine action or state in their actions/state fields." % total_malicious_click
        ]
        result = {"isMaliciousClickBlockingEnabled": True}
        return create_response(
            result=result,
            validation=validation,
            pass_reasons=pass_reasons,
            input_summary=input_summary,
            metadata={"transformationId": "isMaliciousClickBlockingEnabled", "vendor": "Check Point Software Technologies Email Security", "category": "emailsecurity"},
        )
    else:
        fail_reasons = [
            "%d of %d malicious-click events were NOT associated with a block/quarantine action or state (examples: %s)." % (
                total_malicious_click - blocked_count, total_malicious_click, ", ".join([str(x) for x in unblocked_examples]) if unblocked_examples else "n/a"
            )
        ]
        result = {"isMaliciousClickBlockingEnabled": False}
        return create_response(
            result=result,
            validation=validation,
            fail_reasons=fail_reasons,
            recommendations=["Enable enforcement (block/quarantine) action for Click-Time Protection verdicts flagged malicious, rather than log-only mode."],
            input_summary=input_summary,
            metadata={"transformationId": "isMaliciousClickBlockingEnabled", "vendor": "Check Point Software Technologies Email Security", "category": "emailsecurity"},
        )
