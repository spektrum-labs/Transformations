"""Transformation: isbackuploggingenabled_v4 - Commvault (Command Center REST API). Not measured (None) on any body that proves nothing."""
import json
from datetime import datetime


def extract_validation(input_data):
    if isinstance(input_data, dict) and "validation" in input_data and isinstance(input_data["validation"], dict):
        return input_data["validation"]
    return {"status": "unknown", "errors": [], "warnings": ["Legacy input format - no schema validation performed"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None,
                    transformation_errors=None, api_errors=None, additional_findings=None):
    """Standardized 5-section transformation response."""
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    transform_err_list = transformation_errors or []
    response_metadata = {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "2.0"}
    if metadata:
        response_metadata.update(metadata)
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if api_err_list else "success", "errors": api_err_list},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": "error" if transform_err_list else "success",
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


WRAPPERS = ["result", "response", "apiResponse", "api_response", "Output", "data", "_response_data"]


def error_in(cur):
    """A short error string when a vendor/IS error body is in hand, else None."""
    if cur.get("errors") or cur.get("error") is True or isinstance(cur.get("error"), (str, dict)):
        detail = cur.get("errors") or cur.get("error") or cur.get("message") or "error"
        return json.dumps(detail)[:300]
    code = cur.get("status_code") or cur.get("statusCode") or cur.get("status")
    if isinstance(code, int) and not isinstance(code, bool) and code >= 400:
        return "HTTP " + str(code) + ": " + json.dumps(cur.get("message") or cur.get("detail") or "")[:200]
    return None


def find_key(obj, wanted):
    """(container_dict, error) for the first dict, through any wrapper, that carries key `wanted`."""
    cur = obj
    for depth in range(8):
        if isinstance(cur, str):
            try:
                cur = json.loads(cur)
            except Exception:
                return None, None
        if not isinstance(cur, dict):
            return None, None
        if wanted in cur:
            return cur, None
        problem = error_in(cur)
        if problem is not None:
            return None, problem
        nxt = None
        for key in WRAPPERS:
            if isinstance(cur.get(key), (dict, str)):
                nxt = cur.get(key)
                break
        if nxt is None:
            return None, None
        cur = nxt
    return None, None


def raw_body(input):
    # input.get("data") makes Token-Service pass the undrilled response in a {data, validation}
    # envelope, so the pagination block stays visible and a partial read is caught.
    if isinstance(input, dict) and "validation" in input:
        return input.get("data")
    return input


def parse_time(text):
    """Naive-UTC datetime from an ISO-8601 string, or None."""
    if not isinstance(text, str) or len(text) < 19:
        return None
    try:
        return datetime.fromisoformat(text[:19])
    except Exception:
        return None


def pct(part, whole):
    return round(100.0 * part / whole, 2) if whole else None


VENDOR = "Commvault"


def not_measured(key, problem, validation):
    return create_response(
        result={key: None},
        validation=validation,
        fail_reasons=[problem],
        api_errors=[problem],
        metadata={"transformationId": key, "vendor": VENDOR, "category": "backups"},
    )


def commvault_error(cur):
    """Commvault answers some failures with HTTP 200 and errorCode/errorMessage or errList."""
    if not isinstance(cur, dict):
        return None
    code = cur.get("errorCode")
    if code not in (None, 0, "0"):
        return "Commvault error " + str(code) + ": " + str(cur.get("errorMessage") or cur.get("errorString") or "")[:200]
    errs = cur.get("errList")
    if isinstance(errs, list) and len(errs) > 0:
        return "Commvault errList: " + json.dumps(errs[0])[:200]
    err = cur.get("error")
    if isinstance(err, dict) and err.get("errorCode") not in (None, 0, "0"):
        return "Commvault error " + str(err.get("errorCode")) + ": " + str(err.get("errorString") or err.get("errorMessage") or "")[:200]
    return None


def commvault_box(input, wanted):
    """(container, problem): the dict carrying `wanted` through IS wrappers, or why there is none."""
    body = raw_body(input)
    if isinstance(body, str):
        text = body.strip()
        if text.startswith("<"):
            return None, "Commvault answered with HTML or XML, not JSON (the method must send Accept: application/json)."
    box, problem = find_key(body, wanted)
    if problem is not None:
        return None, problem
    if box is None:
        return None, None
    problem = commvault_error(box)
    if problem is not None:
        return None, problem
    return box, None


def as_int(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value.strip())
    return None


def truthy(value):
    if isinstance(value, bool):
        return value
    n = as_int(value)
    if n is not None:
        return n != 0
    if isinstance(value, str):
        return value.strip().lower() in ("true", "yes", "enabled")
    return False


# Method: getCommServeEvents
#   GET {serverUrl}/Events -> commservEvents[] {id, eventCode, timeSource (epoch seconds), severity,
#   jobId, subsystem, description}: the CommServe event log (Command Center > Events).
# Source: Commvault's public Python SDK (github.com/Commvault/cvpysdk, cvpysdk/eventviewer.py:
#   Events.events() reads response["commservEvents"]; services GET_EVENTS "Events").
#
# isBackupLoggingEnabled = True when the CommServe event log holds at least one event recorded in the
# last 7 days, i.e. the CommCell is logging its backup activity now. False when events are returned
# but the newest is older than 7 days (logging has stopped). None when the event list is missing,
# empty (no evidence either way: a narrowly scoped account sees no events) or an error.

from datetime import timezone

WINDOW_DAYS = 7


def transform(input):
    key = "isBackupLoggingEnabled"
    validation = extract_validation(input)
    box, problem = commvault_box(input, "commservEvents")
    if problem is not None:
        return not_measured(key, "Commvault returned an error instead of the event log: " + problem, validation)
    if box is None or not isinstance(box.get("commservEvents"), list):
        return not_measured(key, "No Commvault event list in the response; nothing to evaluate.", validation)
    events = [e for e in box.get("commservEvents") if isinstance(e, dict)]
    stamps = []
    for event in events:
        when = as_int(event.get("timeSource"))
        if when is not None and when > 0 and event.get("id") is not None:
            stamps.append(when)
    if not stamps:
        return not_measured(key, "The Commvault event log returned no dated events; logging cannot be judged.", validation)
    newest = max(stamps)
    now = datetime.now(timezone.utc).timestamp()
    age_days = round((now - newest) / 86400.0, 1)
    ok = age_days <= WINDOW_DAYS
    recent = len([s for s in stamps if (now - s) / 86400.0 <= WINDOW_DAYS])
    text = "Newest CommServe event is " + str(age_days) + " days old; " + str(recent) + " of " + str(len(stamps)) + " returned events are from the last " + str(WINDOW_DAYS) + " days."
    return create_response(
        result={key: ok, "recentEvents": recent, "newestEventAgeDays": age_days},
        validation=validation,
        pass_reasons=[text] if ok else [],
        fail_reasons=[] if ok else [text],
        recommendations=[] if ok else ["Check that the CommServe services are running and recording events (Command Center > Events)."],
        input_summary={"eventsReturned": len(events), "datedEvents": len(stamps)},
        metadata={"transformationId": key, "vendor": VENDOR, "category": "backups"},
    )
