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


BLOCK_ACTION_TOKENS = ["block", "quarantine", "remove", "restrict", "disable"]
LOG_ONLY_TOKENS = ["log", "dismiss", "acknowledge", "severitychange"]


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, dict) else {}

    api_errors = []
    if data.get("error") is True or data.get("statusCode") == 401 or data.get("errorType") == "authentication":
        api_errors.append(
            "API returned an authentication error: %s" % data.get("errorMessage", "unknown error")
        )
        return create_response(
            result={"isMaliciousClickBlockingEnabled": False},
            validation=validation,
            fail_reasons=[
                "Could not retrieve security events from queryEvents due to an authentication failure; "
                "no malicious-URL click events could be inspected to confirm blocking."
            ],
            recommendations=[
                "Verify the clientId/clientSecret credentials used to authenticate against the "
                "Check Point Harmony Email Security API are valid and have not expired."
            ],
            input_summary={"rawErrorType": data.get("errorType"), "statusCode": data.get("statusCode")},
            api_errors=api_errors,
        )

    items = data.get("responseData") or data.get("data") or []
    if not isinstance(items, list):
        items = []

    malicious_url_events = []
    for item in items:
        if not isinstance(item, dict):
            continue
        event_type = (item.get("type") or "")
        if isinstance(event_type, str) and "malicious url" in event_type.lower():
            malicious_url_events.append(item)

    total_malicious = len(malicious_url_events)

    blocked_count = 0
    logged_only_count = 0
    sample_states = []
    for ev in malicious_url_events:
        state = (ev.get("state") or "")
        actions = ev.get("actions") or []
        available_actions = ev.get("availableEventActions") or []
        combined_tokens = []
        if isinstance(state, str):
            combined_tokens.append(state.lower())
        if isinstance(actions, list):
            for a in actions:
                if isinstance(a, str):
                    combined_tokens.append(a.lower())
                elif isinstance(a, dict):
                    an = a.get("actionName") or a.get("name") or ""
                    if isinstance(an, str):
                        combined_tokens.append(an.lower())
        is_blocked = False
        for tok in combined_tokens:
            for b in BLOCK_ACTION_TOKENS:
                if b in tok:
                    is_blocked = True
        if is_blocked:
            blocked_count = blocked_count + 1
        else:
            only_log = False
            for tok in combined_tokens:
                for l in LOG_ONLY_TOKENS:
                    if l in tok:
                        only_log = True
            if only_log:
                logged_only_count = logged_only_count + 1
        if len(sample_states) < 5:
            sample_states.append(state)

    if total_malicious == 0:
        return create_response(
            result={"isMaliciousClickBlockingEnabled": False},
            validation=validation,
            fail_reasons=[
                "No events of type 'Malicious URL' were returned by queryEvents in this response, "
                "so click-time blocking behavior could not be confirmed from event evidence."
            ],
            recommendations=[
                "Broaden the /event/query filter/time-window to include Malicious URL events, or "
                "trigger a test click on a rewritten malicious URL to generate an evaluable event."
            ],
            input_summary={"totalMaliciousUrlEvents": 0, "totalEventsInPage": len(items)},
        )

    is_enabled = blocked_count > 0

    if is_enabled:
        pass_reasons = [
            (
                "%d of %d 'Malicious URL' events carry a blocking action/state "
                "(e.g. block/quarantine/remove found in state=%s or actions), confirming clicks "
                "on rewritten malicious URLs are actively blocked, not just logged."
            )
            % (blocked_count, total_malicious, sample_states)
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            (
                "Found %d 'Malicious URL' events but none carried a blocking action/state "
                "(%d were logged/dismissed-only via state/actions such as %s); clicks on "
                "rewritten malicious URLs appear to be logged rather than actively blocked."
            )
            % (total_malicious, logged_only_count, sample_states)
        ]
        recommendations = [
            "Enable the click-time blocking/enforcement setting for the URL protection engine so "
            "that malicious-verdict clicks are blocked, not merely logged for review."
        ]

    return create_response(
        result={"isMaliciousClickBlockingEnabled": is_enabled},
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalMaliciousUrlEvents": total_malicious,
            "blockedCount": blocked_count,
            "loggedOnlyCount": logged_only_count,
        },
    )
