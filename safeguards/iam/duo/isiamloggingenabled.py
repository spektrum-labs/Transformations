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
# username and result. The 40301 refusal is a measured false (the log cannot be pulled for
# monitoring). Any other handed-over error, or a body with no event, proves nothing and is
# reported as a data-collection error, never judged.

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


def access_forbidden(data):
    if not isinstance(data, dict):
        return False
    marker = data.get("vendorErrorAsResponse")
    if not isinstance(marker, dict) or marker.get("status") != 403:
        return False
    body = marker.get("body")
    if isinstance(body, str):
        try:
            body = json.loads(body)
        except ValueError:
            return False
    return isinstance(body, dict) and body.get("code") == ACCESS_FORBIDDEN_CODE \
        and body.get("message") == "Access forbidden"


def transform(input):
    data, validation = load(input)
    if access_forbidden(data):
        return create_response(
            result={KEY: False, "authLogEventCount": 0},
            validation=validation,
            input_summary={"vendorStatus": 403, "vendorCode": ACCESS_FORBIDDEN_CODE},
            fail_reasons=["Duo refused the authentication log endpoint with HTTP 403, code 40301 "
                          "\"Access forbidden\": authentication activity cannot be pulled for monitoring."],
            recommendations=["In the Duo Admin Panel, enable \"Grant read log\" on the Admin API application "
                             "used for Spektrum and forward the logs to your monitoring platform."],
        )
    if isinstance(data, dict) and "vendorErrorAsResponse" in data:
        return create_response(
            result={KEY: False, "authLogEventCount": 0},
            validation=validation,
            api_errors=["Duo returned an error instead of authentication log data: %s"
                        % str(data.get("vendorErrorAsResponse"))[:300]],
        )

    endpoint, items = log_events(data)
    events = objects_with(items, "txid")
    if events is None:
        events = objects_with(items, "timestamp")
    if events is None:
        return create_response(
            result={KEY: False, "authLogEventCount": 0},
            validation=validation,
            api_errors=["No Duo authentication log events in the response from %s."
                        % (endpoint or "the authentication log endpoint")],
        )

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
