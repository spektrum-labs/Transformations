import json
from datetime import datetime, timezone

# isIAMLoggingEnabled -- is Duo authentication activity logged and retrievable for
# monitoring?
#
# Source: either authentication log method; both opt in to vendorErrorAsResponse for Duo's
# 403 / 40301 "Access forbidden", which Duo returns when the Admin API application lacks
# "Grant read log"; Integration-Service hands it over nested as
# {"vendorErrorAsResponse": {"status": 403, "bodyContains": ..., "body": ...}}.
#   v1 getAuthenticationLogs  GET /admin/v1/logs/authentication
#       {"stat": "OK", "response": [{"txid", "timestamp", "username", "result", ...}]}
#   v2 getAuthLogs            GET /admin/v2/logs/authentication (mintime now-30d, sort ts:desc)
#       {"authlogs": [{"txid", "timestamp", "user": {"name"}, "result", ...}], "metadata": {...}}
# Both shapes are read the same way (v2 names the user under user.name); the evidence names
# the endpoint the events came from and the real time span of the events read.
#
# Verdict: true when the log API returns authentication events carrying timestamp,
# username and result; false only when events came back but none carries all three (activity
# cannot be attributed). Anything that is not a read of the log is Unevaluated (every key None,
# data-collection error), never False: the 403 / 40301 refusal (names "Grant read log"), any
# other handed-over vendor error, and a body with no event (an empty list is what a failed read
# defaults to, and a quiet tenant looks the same, so it cannot show logging is off).

KEY = "isIAMLoggingEnabled"
ACCESS_FORBIDDEN_CODE = 40301
V1_ENDPOINT = "/admin/v1/logs/authentication"
V2_ENDPOINT = "/admin/v2/logs/authentication"


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for i in range(3):
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
                    recommendations=None, input_summary=None, api_errors=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if api_err_list else "success", "errors": api_err_list},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {"status": "success", "errors": [], "inputSummary": input_summary or {}},
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": [],
            },
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "2.0",
                "transformationId": KEY,
                "vendor": "Duo",
                "category": "iam",
            },
        },
    }



INACTIVE_STATUSES = ("disabled", "locked out", "pending deletion", "deleted")


def load(input):
    if isinstance(input, (str, bytes)):
        try:
            input = json.loads(input)
        except ValueError:
            input = {}
    return extract_input(input)


def log_events(data):
    """(endpoint, list) holding the authentication log events in a v1 or v2 body, else (None, None)."""
    if isinstance(data, dict) and isinstance(data.get("response"), dict) \
            and isinstance(data["response"].get("authlogs"), list):
        data = data["response"]  # raw v2 body that no wrapper unwrapped (e.g. inside enriched "data")
    if isinstance(data, dict) and isinstance(data.get("authlogs"), list):
        return V2_ENDPOINT, data["authlogs"]
    if isinstance(data, list):
        return V1_ENDPOINT, data
    if isinstance(data, dict):
        items = data.get("response")
        if items is None:
            items = data.get("data")
        if isinstance(items, list):
            return V1_ENDPOINT, items
    return None, None


def objects_with(items, id_field):
    """The vendor objects in items carrying id_field; None when there is no such object."""
    if not isinstance(items, list):
        return None
    found = [x for x in items if isinstance(x, dict) and x.get(id_field) not in (None, "")]
    return found if found else None


def event_username(e):
    """v1 carries "username"; v2 carries "user": {"name": ...}."""
    name = e.get("username")
    if name in (None, ""):
        user = e.get("user")
        if isinstance(user, dict):
            name = user.get("name")
    return name


def event_epoch(e):
    ts = e.get("timestamp")
    if isinstance(ts, (int, float)) and not isinstance(ts, bool) and ts > 0:
        return float(ts)
    if isinstance(ts, str) and ts.strip().isdigit():
        return float(ts.strip())
    return None


def iso_of(epoch_seconds):
    try:
        return datetime.fromtimestamp(epoch_seconds, timezone.utc).isoformat()
    except (ValueError, OverflowError, OSError):
        return None


def pct(part, whole):
    return round(100.0 * part / whole, 1) if whole else 0.0


# Integration-Service hands a vendor refusal over as data when the method opts in
# (vendorErrorAsResponse): {"vendorErrorAsResponse": {"status": 403, "bodyContains": ..., "body": <vendor body>}}.
# Duo answers a missing Admin API permission with HTTP 403 {"stat": "FAIL", "code": 40301,
# "message": "Access forbidden"}. That says nothing about the tenant's posture (the log was never
# read), so every key stays None (Unevaluated) and the error names the permission to grant. Any
# other handed-over refusal is Unevaluated with errorCode "vendor_refusal" and names no permission.
REFUSAL_FORBIDDEN_CODE = ACCESS_FORBIDDEN_CODE
PERMISSION_NOT_GRANTED = "permission_not_granted"
VENDOR_REFUSAL = "vendor_refusal"
REQUIRED_PERMISSION = "Grant read log"
REFUSAL_KEYS = [KEY, "authLogEventCount", "completeEventCount", "completeEventPercentage", "loggedUserCount"]
REFUSAL_ENDPOINT = "the Duo authentication log endpoint (" + V1_ENDPOINT + " or " + V2_ENDPOINT + ")"


def refusal_decoded(body):
    """A vendor body or whole input as an object: dicts as they are, JSON text or bytes parsed, else None."""
    if isinstance(body, bytes):
        try:
            body = body.decode("utf-8")
        except Exception:
            return None
    if isinstance(body, str):
        try:
            return json.loads(body)
        except Exception:
            return None
    return body


def refusal_envelope(value):
    """The dict carrying vendorErrorAsResponse: the input itself or one level inside it, else None."""
    value = refusal_decoded(value)
    if not isinstance(value, dict):
        return None
    if "vendorErrorAsResponse" in value:
        return value
    for k in value:
        inner = value[k]
        if isinstance(inner, dict) and "vendorErrorAsResponse" in inner:
            return inner
    return None


def refusal_unevaluated(envelope):
    marker = envelope.get("vendorErrorAsResponse")
    status = marker.get("status") if isinstance(marker, dict) else None
    body = refusal_decoded(marker.get("body")) if isinstance(marker, dict) else None
    forbidden = (status == 403 and isinstance(body, dict)
                 and body.get("code") == REFUSAL_FORBIDDEN_CODE and body.get("message") == "Access forbidden")
    result = {}
    for k in REFUSAL_KEYS:
        result[k] = None
    if forbidden:
        problem = ("PERMISSION-NOT-GRANTED: Duo refused the call to " + REFUSAL_ENDPOINT + " with HTTP 403 code 40301 "
                   "(Access forbidden) because the Admin API application lacks the \"" + REQUIRED_PERMISSION
                   + "\" permission. Nothing was measured; this is not a posture result.")
        recommendation = ("In the Duo Admin Panel, open the Admin API application used for Spektrum and enable the \""
                          + REQUIRED_PERMISSION + "\" permission; the integration key and secret do not change.")
    else:
        problem = ("Duo refused the call to " + REFUSAL_ENDPOINT + " (HTTP " + str(status)[:10]
                   + "); nothing was measured.")
        recommendation = "Confirm the Duo Admin API credentials are valid and the Admin API application is enabled."
    out = create_response(result, None, fail_reasons=[problem], api_errors=[problem],
                          recommendations=[recommendation])
    collection = out["additionalInfo"]["dataCollection"]
    if forbidden:
        collection["errorCode"] = PERMISSION_NOT_GRANTED
        collection["requiredPermission"] = REQUIRED_PERMISSION
    else:
        collection["errorCode"] = VENDOR_REFUSAL
    return out


def unreadable(reason):
    """Nothing was measured: every key None, never False."""
    result = {}
    for k in REFUSAL_KEYS:
        result[k] = None
    problem = ("No Duo authentication log events (txid or timestamp) could be read (" + reason
               + "). An empty or failed read cannot show whether authentication activity is logged, so this is "
               "not a posture result.")
    return create_response(
        result=result, api_errors=[problem], fail_reasons=[problem],
        recommendations=["Confirm the Duo Admin API credentials are valid and the Admin API application "
                         "has the \"" + REQUIRED_PERMISSION + "\" permission."],
    )


def transform(input):
    try:
        refusal = refusal_envelope(input)
        data = None
        validation = None
        if refusal is None:
            data, validation = load(input)
            refusal = refusal_envelope(data)
        if refusal is not None:
            return refusal_unevaluated(refusal)
        return measure(data, validation)
    except Exception:
        return unreadable("the response could not be processed")


def measure(data, validation):
    endpoint, items = log_events(data)
    events = objects_with(items, "txid")
    if events is None:
        events = objects_with(items, "timestamp")
    if events is None:
        return unreadable("no event in the response from %s" % (endpoint or "the authentication log endpoint"))

    complete = 0
    users = []
    oldest = None
    newest = None
    for e in events:
        name = event_username(e)
        if e.get("timestamp") not in (None, "") and e.get("result") not in (None, "") \
                and name not in (None, ""):
            complete = complete + 1
            if name not in users:
                users.append(name)
        ts = event_epoch(e)
        if ts is not None:
            if oldest is None or ts < oldest:
                oldest = ts
            if newest is None or ts > newest:
                newest = ts

    oldest_iso = iso_of(oldest) if oldest is not None else None
    newest_iso = iso_of(newest) if newest is not None else None
    if oldest_iso is None:
        span = "with no readable timestamp"
    elif oldest_iso == newest_iso:
        span = "all at %s" % newest_iso
    else:
        span = "from %s to %s" % (oldest_iso, newest_iso)
    summary = {
        "authLogEventCount": len(events),
        "completeEventCount": complete,
        "completeEventPercentage": pct(complete, len(events)),
        "loggedUserCount": len(users),
        "endpoint": endpoint,
        "oldestEventTimestamp": oldest_iso,
        "newestEventTimestamp": newest_iso,
    }
    result = {KEY: complete > 0}
    for k in ("authLogEventCount", "completeEventCount", "completeEventPercentage", "loggedUserCount"):
        result[k] = summary[k]
    if result[KEY]:
        return create_response(
            result=result, validation=validation, input_summary=summary,
            pass_reasons=["Duo authentication logs (%s) returned %d events %s (%d with timestamp, username "
                          "and result) covering %d users." % (endpoint, len(events), span, complete, len(users))],
        )
    return create_response(
        result=result, validation=validation, input_summary=summary,
        fail_reasons=["Duo authentication logs (%s) returned %d events %s but none carries timestamp, username "
                      "and result, so activity cannot be attributed." % (endpoint, len(events), span)],
    )
