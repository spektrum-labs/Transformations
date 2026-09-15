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


SANDBOX_KEYWORDS = [
    "sandbox",
    "detonat",
    "emulat",
    "threatcloud",
    "zero-day",
    "zero day",
]

MALWARE_TYPES = ["malware", "attachment", "threat_emulation", "threatemulation"]


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, dict) else {}

    api_errors = []
    if data.get("error") or data.get("errorType") == "authentication" or data.get("statusCode") == 401:
        api_errors.append(str(data.get("errorMessage") or data.get("message") or "API error"))

    events = data.get("responseData") or []
    if not isinstance(events, list):
        events = []

    total_events = len(events)
    detonation_events = []

    for ev in events:
        if not isinstance(ev, dict):
            continue
        ev_type = str(ev.get("type") or "").lower()
        description = str(ev.get("description") or "").lower()
        add_data = ev.get("additionalData")
        add_data_str = json.dumps(add_data).lower() if add_data else ""
        ev_data = ev.get("data")
        ev_data_str = json.dumps(ev_data).lower() if ev_data else ""

        haystack = ev_type + " " + description + " " + add_data_str + " " + ev_data_str

        is_malware_type = False
        for mt in MALWARE_TYPES:
            if mt in ev_type:
                is_malware_type = True
                break

        has_sandbox_keyword = False
        for kw in SANDBOX_KEYWORDS:
            if kw in haystack:
                has_sandbox_keyword = True
                break

        if is_malware_type and has_sandbox_keyword:
            detonation_events.append(ev)
        elif has_sandbox_keyword:
            detonation_events.append(ev)

    enabled = len(detonation_events) > 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if api_errors:
        fail_reasons.append(
            "Unable to confirm attachment sandbox detonation: API returned an error (%s) instead of event data." % "; ".join(api_errors)
        )
        recommendations.append(
            "Verify Check Point Harmony Email API credentials (clientId/accessKey) and re-run the event query to retrieve malware/attachment detonation events."
        )
        enabled = False
    elif total_events == 0:
        fail_reasons.append(
            "queryEvents returned zero events in responseData, so no sandbox detonation verdicts (e.g. malware/attachment type events referencing ThreatCloud, sandbox, or detonation) could be observed."
        )
        recommendations.append(
            "Confirm attachment sandboxing (Threat Emulation) is enabled in the Harmony Email policy, then re-run once qualifying events exist."
        )
    elif enabled:
        sample = detonation_events[0]
        pass_reasons.append(
            "Found %d of %d queried events with malware/attachment type and sandbox/detonation indicators (e.g. eventId=%s, type=%s, description snippet=%s), confirming attachments are routed through ThreatCloud sandbox detonation before delivery."
            % (
                len(detonation_events),
                total_events,
                str(sample.get("eventId")),
                str(sample.get("type")),
                str(sample.get("description"))[:120],
            )
        )
    else:
        fail_reasons.append(
            "Queried %d events but none contained malware/attachment type or sandbox/detonation/ThreatCloud keywords in type, description, data, or additionalData fields."
            % total_events
        )
        recommendations.append(
            "Enable Threat Emulation (sandboxing) for attachments in the Harmony Email Collaboration policy so detonation verdicts are generated and queryable."
        )

    result = {
        "isAttachmentSandboxDetonationEnabled": bool(enabled),
        "totalEventsQueried": total_events,
        "detonationEventCount": len(detonation_events),
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalEvents": total_events, "detonationEvents": len(detonation_events)},
        metadata={
            "transformationId": "isAttachmentSandboxDetonationEnabled",
            "vendor": "Check Point Software Technologies Email Security",
            "category": "emailsecurity",
        },
        api_errors=api_errors,
    )
