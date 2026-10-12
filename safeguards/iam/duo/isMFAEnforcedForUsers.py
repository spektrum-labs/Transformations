import json
from datetime import datetime

# isMFAEnforcedForUsers -- is Duo MFA enforced for every active user?
#
# Source: GET /admin/v1/users (method getUsers, returnSpec {"response": [...]}). A Duo user
# is held to MFA when it is enrolled (is_enrolled true) and its status is not "bypass"
# (bypass skips the second factor). Disabled, locked-out and pending-deletion users are
# not active and are left out of the denominator.
#
# Verdict: true when every active user is enrolled and none is in bypass.
# mfaEnforcedUserPercentage is the measure. A body with no user object (user_id) proves
# nothing -- an error collapses to the returnSpec default [] -- so it is Unevaluated (every key
# None, data-collection error), never judged and never False: an empty, error or non-list body,
# an exception, Duo's 403 / 40301 refusal (names "Grant resource - Read", the Admin API permission
# Duo documents for GET /admin/v1/users) and any other handed-over vendor error
# (vendorErrorAsResponse). A real read still measures: users came back and some are in bypass or not
# enrolled is a measured False; users came back and none is active is a measured False with 0.0.

KEY = "isMFAEnforcedForUsers"
USER_FIELDS = ("username", "email", "user_id")
REFUSAL_KEYS = [KEY, "usersReturned", "activeUsers", "mfaEnforcedUsers", "mfaEnforcedUserPercentage",
                "bypassUserCount", "unenrolledUserCount"]


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


# #101: findings name the affected accounts (same shape as mfa/azure/legacyauthblocked.py). The first
# reason names at most MAX_NAMED, then "and N more"; inputSummary.affectedAccounts carries at most
# MAX_AFFECTED, with the full count in affectedAccountCount. The verdict never reads them.
MAX_NAMED = 20
MAX_AFFECTED = 50


def account_name(obj, fields):
    for field in fields:
        value = obj.get(field)
        if value not in (None, ""):
            return str(value).strip()[:100]
    return "unknown"


def name_list(items):
    """At most MAX_NAMED identifiers, then 'and N more'."""
    shown = ", ".join(items[:MAX_NAMED])
    if len(items) > MAX_NAMED:
        shown = shown + " and " + str(len(items) - MAX_NAMED) + " more"
    return shown


def affected_line(scope, affected, total, what):
    """One line naming the tool and its scope: 'Duo (<scope>): N of M <what>: a, b and K more'."""
    return "Duo (%s): %d of %d %s: %s" % (scope, len(affected), total, what, name_list(affected))


def with_affected(summary, affected):
    summary["affectedAccounts"] = affected[:MAX_AFFECTED]
    summary["affectedAccountCount"] = len(affected)
    return summary


# Integration-Service hands a vendor refusal over as data when the method opts in
# (vendorErrorAsResponse): {"vendorErrorAsResponse": {"status": 403, "bodyContains": ..., "body": <vendor body>}}.
# Duo answers a missing Admin API permission with HTTP 403 {"stat": "FAIL", "code": 40301,
# "message": "Access forbidden"}; GET /admin/v1/users needs "Grant resource - Read" (Duo Admin API docs,
# Retrieve Users). That says nothing about the tenant's posture, so every key stays None (Unevaluated) and
# the error names the permission to grant. Any other handed-over refusal is Unevaluated with errorCode
# "vendor_refusal" and names no permission.
REFUSAL_FORBIDDEN_CODE = 40301
PERMISSION_NOT_GRANTED = "permission_not_granted"
VENDOR_REFUSAL = "vendor_refusal"
REQUIRED_PERMISSION = "Grant resource - Read"
REFUSAL_ENDPOINT = "GET /admin/v1/users"


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
    problem = ("No Duo user objects (user_id) could be read from the getUsers response (" + reason
               + "). An empty or failed read cannot show whether MFA is enforced, so this is not a posture result.")
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
    users = objects_with(data, "user_id")
    if users is None:
        return unreadable("empty, error or unrecognised body")

    active = 0
    enforced = 0
    bypass = 0
    unenrolled = 0
    bypass_names = []
    unenrolled_names = []
    for u in users:
        status = str(u.get("status") or "").lower()
        if status in INACTIVE_STATUSES:
            continue
        active = active + 1
        if status == "bypass":
            bypass = bypass + 1
            bypass_names.append(account_name(u, USER_FIELDS))
        elif u.get("is_enrolled") is not True:
            unenrolled = unenrolled + 1
            unenrolled_names.append(account_name(u, USER_FIELDS))
        else:
            enforced = enforced + 1

    summary = {
        "usersReturned": len(users),
        "activeUsers": active,
        "mfaEnforcedUsers": enforced,
        "mfaEnforcedUserPercentage": pct(enforced, active),
        "bypassUserCount": bypass,
        "unenrolledUserCount": unenrolled,
    }
    result = {KEY: active > 0 and enforced == active}
    result.update(summary)
    affected = bypass_names + unenrolled_names
    summary = with_affected(dict(summary), affected)

    if result[KEY]:
        return create_response(
            result=result, validation=validation, input_summary=summary,
            pass_reasons=["All %d active Duo users are enrolled in MFA and none is in bypass status." % active],
        )
    if active == 0:
        reasons = ["Duo returned %d users and none is active, so MFA enforcement covers no one." % len(users)]
    else:
        reasons = ["%d of %d active Duo users (%.1f%%) are held to MFA: %d in bypass status, %d not enrolled; %s"
                   % (enforced, active, summary["mfaEnforcedUserPercentage"], bypass, unenrolled,
                      affected_line("active users", affected, active,
                                    "active users are not held to MFA (bypass first, then not enrolled)"))]
    return create_response(
        result=result, validation=validation, input_summary=summary, fail_reasons=reasons,
        recommendations=["Take users out of bypass status and have unenrolled users complete Duo enrollment."],
    )
