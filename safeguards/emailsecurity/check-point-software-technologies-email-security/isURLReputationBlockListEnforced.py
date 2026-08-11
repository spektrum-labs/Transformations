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


BLOCKING_STATES = ["blocked", "quarantined", "remediated", "removed", "deleted"]
FLAG_ONLY_STATES = ["flagged", "detected", "reported", "open"]


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, dict) else {}

    api_errors = []
    if data.get("error") is True or data.get("statusCode") == 401 or data.get("errorType") == "authentication":
        api_errors.append(
            f"API returned an authentication/error response: {data.get('message') or data.get('errorMessage') or 'unknown error'}"
        )
        result = {
            "isURLReputationBlockListEnforced": False,
            "maliciousUrlEventCount": 0,
            "blockedMaliciousUrlEventCount": 0,
        }
        return create_response(
            result=result,
            validation=validation,
            fail_reasons=["Could not retrieve security events because the API call failed authentication; no evidence of URL reputation block-list enforcement could be gathered."],
            recommendations=["Verify API credentials (clientId/clientSecret) and retry the /event/query call to confirm URL reputation blocking status."],
            input_summary={"apiError": True},
            api_errors=api_errors,
            metadata={
                "transformationId": "isURLReputationBlockListEnforced",
                "vendor": "Check Point Software Technologies Email Security",
                "category": "emailsecurity",
            },
        )

    events = data.get("responseData") or []
    if not isinstance(events, list):
        events = []

    malicious_url_events = [
        e for e in events
        if isinstance(e, dict) and str(e.get("type") or "").strip().lower() == "malicious url"
    ]

    blocked_events = []
    flagged_only_events = []
    for e in malicious_url_events:
        state = str(e.get("state") or "").strip().lower()
        if state in BLOCKING_STATES:
            blocked_events.append(e)
        elif state in FLAG_ONLY_STATES:
            flagged_only_events.append(e)
        else:
            actions = e.get("availableEventActions") or []
            if isinstance(actions, list) and any(
                str(a).strip().lower() in BLOCKING_STATES for a in actions
            ):
                blocked_events.append(e)
            else:
                flagged_only_events.append(e)

    total_malicious = len(malicious_url_events)
    total_blocked = len(blocked_events)

    is_enforced = total_malicious > 0 and total_blocked > 0

    result = {
        "isURLReputationBlockListEnforced": is_enforced,
        "maliciousUrlEventCount": total_malicious,
        "blockedMaliciousUrlEventCount": total_blocked,
    }

    if is_enforced:
        sample_ids = [e.get("eventId") for e in blocked_events[:3]]
        pass_reasons = [
            f"Found {total_blocked} of {total_malicious} 'Malicious URL' events with a blocking state (e.g. blocked/quarantined/remediated), sample eventIds: {sample_ids}. This confirms URLs matching known-bad reputation lists are blocked at click-time, not merely flagged."
        ]
        fail_reasons = []
        recommendations = []
    elif total_malicious > 0:
        pass_reasons = []
        fail_reasons = [
            f"Found {total_malicious} 'Malicious URL' events but none carried a blocking state (blocked/quarantined/remediated); observed states were only flag/detect-type, indicating URLs are flagged rather than blocked at click-time."
        ]
        recommendations = [
            "Enable click-time blocking/quarantine action for Malicious URL detections in the Harmony Email and Collaboration policy so matched URLs are blocked rather than only flagged."
        ]
    else:
        pass_reasons = []
        fail_reasons = [
            "No 'Malicious URL' type events were found in the queried event set, so no evidence of URL reputation block-list enforcement could be confirmed."
        ]
        recommendations = [
            "Confirm the URL reputation / malicious URL detection engine is enabled and generating events, then verify blocking action is configured."
        ]

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalEvents": len(events),
            "maliciousUrlEventCount": total_malicious,
            "blockedMaliciousUrlEventCount": total_blocked,
        },
        api_errors=api_errors,
        metadata={
            "transformationId": "isURLReputationBlockListEnforced",
            "vendor": "Check Point Software Technologies Email Security",
            "category": "emailsecurity",
        },
    )
