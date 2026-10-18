"""
Transformation: isEPPLoggingEnabled
Vendor: ThreatDown (Malwarebytes Nebula)  |  Category: Endpoint Security
Method: getEvents (GET /nebula/v1/events, with the accountid header)

Evidence: the Nebula OpenAPI documents GET /nebula/v1/events ("Retrieve events associated with
your account") as returning {"events": [...], "total_count": int, "next_cursor": str}, each event
carrying id, machine_id, type_name, severity_name and timestamp. Retrieved events ARE the
console's security log records, so their presence is direct evidence that the endpoint agents
are logging to Nebula and that the log is retrievable -- not an inference from a 200.

Rule: true when the response is a recognisable events collection holding at least one event
(the page's events list is non-empty, or total_count is above zero). An empty collection is
false: an account whose agents report nothing has no log to show. An error envelope, a missing
events list, or any other shape is false.

Also returns eventCount (events on the page read), totalCount (the API's total_count, or -1
when absent) and newestEventAt (the latest timestamp on the page).

Proves: ThreatDown is recording endpoint security events for the account and exposing them for
collection. Does not prove: that the customer forwards them to a SIEM (Nebula does not report
who consumes the feed), or how long they are retained.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), (dict, list)):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped or not isinstance(data, dict):
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None,
                    api_errors=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isEPPLoggingEnabled", "vendor": "ThreatDown", "category": "Endpoint Security"}
        }
    }


def api_error_message(data):
    if isinstance(data, dict):
        if data.get("error") is True or str(data.get("error")).lower() == "true":
            return str(data.get("errorMessage") or data.get("message") or "ThreatDown API returned an error")
        for key in ["errorMessage", "errors", "statusCode"]:
            if data.get(key) and "events" not in data:
                return "ThreatDown API returned an error: " + str(data.get(key))[:200]
    return None


def events_collection(data):
    """Return (events, total_count) or (None, None) when the shape is not an events collection."""
    if isinstance(data, list):
        return [e for e in data if isinstance(e, dict)], None
    if isinstance(data, dict) and isinstance(data.get("events"), list):
        total = data.get("total_count")
        if isinstance(total, bool) or not isinstance(total, (int, float)):
            total = None
        return [e for e in data["events"] if isinstance(e, dict)], total
    return None, None


def transform(input):
    criteriaKey = "isEPPLoggingEnabled"
    empty = {criteriaKey: False, "eventCount": 0, "totalCount": -1, "newestEventAt": ""}
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(result=empty, validation=validation,
                                   fail_reasons=["Input validation failed"])

        error = api_error_message(data)
        events, total = events_collection(data)
        if error or events is None:
            reason = error or "Events response not recognised - no events list present"
            return create_response(result=empty, validation=validation, api_errors=[reason],
                                   fail_reasons=[reason],
                                   recommendations=["Verify GET /nebula/v1/events is reachable with the accountid header"])

        stamps = [str(e.get("timestamp")) for e in events if e.get("timestamp")]
        newest = max(stamps) if stamps else ""
        value = len(events) > 0 or (total is not None and total > 0)
        result = {
            criteriaKey: value,
            "eventCount": len(events),
            "totalCount": int(total) if total is not None else -1,
            "newestEventAt": newest,
        }
        if value:
            passes = [f"ThreatDown returned {len(events)} event(s) on the first page (total_count {result['totalCount']}); newest {newest or 'undated'}"]
            fails = []
            recs = []
        else:
            passes = []
            fails = ["ThreatDown returned no events for the account: nothing is being logged to Nebula"]
            recs = ["Confirm endpoint agents are installed and reporting to the Nebula console"]
        return create_response(result=result, validation=validation, pass_reasons=passes,
                               fail_reasons=fails, recommendations=recs, input_summary=result)
    except Exception as e:
        return create_response(result=empty, validation={"status": "error", "errors": [], "warnings": []},
                               transformation_errors=[str(e)], fail_reasons=[f"Transformation error: {str(e)}"])
