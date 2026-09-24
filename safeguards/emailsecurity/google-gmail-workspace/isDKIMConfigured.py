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
                if key in data and isinstance(data.get(key), (dict, list)):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped or not isinstance(data, dict):
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
    data = data if isinstance(data, (dict, list)) else {}

    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = data.get("items") or data.get("data") or []
        if not isinstance(items, list):
            items = []
    else:
        items = []

    matches = []
    for item in items:
        if not isinstance(item, dict):
            continue
        idobj = item.get("id") or {}
        activity_time = idobj.get("time") if isinstance(idobj, dict) else None
        events = item.get("events") or []
        if not isinstance(events, list):
            continue
        for ev in events:
            if not isinstance(ev, dict):
                continue
            try:
                ev_str = json.dumps(ev).lower()
            except Exception:
                ev_str = str(ev).lower()
            if "dkim" in ev_str:
                matches.append({"time": activity_time, "event": ev, "raw": ev_str})

    total_activities = len(items)
    total_dkim_events = len(matches)

    dkim_configured = False
    latest_event_time = None
    latest_raw = None

    if matches:
        # pick most recent by ISO8601 lexical order (format is fixed-width so sortable)
        best = None
        for m in matches:
            t = m.get("time") or ""
            if best is None or t > (best.get("time") or ""):
                best = m
        latest_event_time = best.get("time")
        latest_raw = best.get("raw") or ""

        if "stop" in latest_raw or "disable" in latest_raw or "\"false\"" in latest_raw:
            dkim_configured = False
        elif "start" in latest_raw or "enable" in latest_raw or "\"true\"" in latest_raw:
            dkim_configured = True
        else:
            # DKIM mentioned but polarity unclear
            dkim_configured = False

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if matches and dkim_configured:
        pass_reasons.append(
            f"Most recent DKIM-related admin audit event at {latest_event_time} indicates DKIM authentication was started/enabled (matched {total_dkim_events} DKIM event(s) out of {total_activities} admin activities scanned)."
        )
    elif matches and not dkim_configured:
        fail_reasons.append(
            f"Most recent DKIM-related admin audit event at {latest_event_time} indicates DKIM authentication was stopped/disabled or its state could not be confirmed as enabled (matched {total_dkim_events} DKIM event(s) out of {total_activities} admin activities scanned)."
        )
        recommendations.append(
            "Enable DKIM authentication for the domain in Admin console > Apps > Google Workspace > Gmail > Authenticate email, and verify the DKIM record is published in DNS."
        )
    else:
        fail_reasons.append(
            f"No DKIM authentication Start/Stop events were found in the {total_activities} admin audit activities scanned (0 matches). Admin audit log does not confirm DKIM is configured."
        )
        recommendations.append(
            "Enable DKIM authentication for the domain in Admin console > Apps > Google Workspace > Gmail > Authenticate email, and verify the DKIM record is published in DNS. Then re-run this check so the enabling event appears in the admin audit log."
        )

    result = {
        "isDKIMConfigured": dkim_configured,
        "totalAdminActivitiesScanned": total_activities,
        "totalDKIMEventsFound": total_dkim_events,
        "latestDKIMEventTime": latest_event_time,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalAdminActivitiesScanned": total_activities,
            "totalDKIMEventsFound": total_dkim_events,
        },
        metadata={
            "transformationId": "isDKIMConfigured",
            "vendor": "Google Gmail Workspace",
            "category": "emailsecurity",
        },
    )
