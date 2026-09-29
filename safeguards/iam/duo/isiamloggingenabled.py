import json
from datetime import datetime

# isIAMLoggingEnabled -- is Duo authentication activity logged and retrievable for
# monitoring?
#
# Source: GET /admin/v1/logs/authentication (method getAuthenticationLogs). The method opts
# in to vendorErrorAsResponse for Duo's 403 / 40301 "Access forbidden", which Duo returns
# when the Admin API application lacks "Grant read log"; Integration-Service hands it over
# nested as {"vendorErrorAsResponse": {"status": 403, "bodyContains": ..., "body": ...}}.
#
# Verdict: true when the log API returns authentication events carrying timestamp,
# username and result. The 40301 refusal is a measured false (the log cannot be pulled for
# monitoring). Any other handed-over error, or a body with no event, proves nothing and is
# reported as a data-collection error, never judged.

KEY = "isIAMLoggingEnabled"
ACCESS_FORBIDDEN_CODE = 40301


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


def objects_with(data, id_field):
    """The list of vendor objects carrying id_field; None when the body holds no such object."""
    items = data
    if isinstance(data, dict):
        items = data.get("response")
        if items is None:
            items = data.get("data")
    if not isinstance(items, list):
        return None
    found = [x for x in items if isinstance(x, dict) and x.get(id_field) not in (None, "")]
    return found if found else None


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

    events = objects_with(data, "txid")
    if events is None:
        events = objects_with(data, "timestamp")
    if events is None:
        return create_response(
            result={KEY: False, "authLogEventCount": 0},
            validation=validation,
            api_errors=["No Duo authentication log events in the getAuthenticationLogs response."],
        )

    complete = 0
    users = []
    for e in events:
        if e.get("timestamp") not in (None, "") and e.get("result") not in (None, "") \
                and e.get("username") not in (None, ""):
            complete = complete + 1
            if e.get("username") not in users:
                users.append(e.get("username"))

    summary = {
        "authLogEventCount": len(events),
        "completeEventCount": complete,
        "completeEventPercentage": pct(complete, len(events)),
        "loggedUserCount": len(users),
    }
    result = {KEY: complete > 0}
    result.update(summary)
    if result[KEY]:
        return create_response(
            result=result, validation=validation, input_summary=summary,
            pass_reasons=["Duo authentication logs returned %d events (%d with timestamp, username and result) "
                          "covering %d users." % (len(events), complete, len(users))],
        )
    return create_response(
        result=result, validation=validation, input_summary=summary,
        fail_reasons=["Duo returned %d authentication log events but none carries timestamp, username and "
                      "result, so activity cannot be attributed." % len(events)],
    )
