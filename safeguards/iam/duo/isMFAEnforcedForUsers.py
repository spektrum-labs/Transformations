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
# nothing -- an error collapses to the returnSpec default [] -- and is reported as a
# data-collection error, never judged.

KEY = "isMFAEnforcedForUsers"


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


def transform(input):
    data, validation = load(input)
    users = objects_with(data, "user_id")
    if users is None:
        return create_response(
            result={KEY: False, "mfaEnforcedUserPercentage": 0.0, "activeUsers": 0},
            validation=validation,
            api_errors=["No Duo user objects (user_id) in the getUsers response."],
        )

    active = 0
    enforced = 0
    bypass = 0
    unenrolled = 0
    for u in users:
        status = str(u.get("status") or "").lower()
        if status in INACTIVE_STATUSES:
            continue
        active = active + 1
        if status == "bypass":
            bypass = bypass + 1
        elif u.get("is_enrolled") is not True:
            unenrolled = unenrolled + 1
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

    if result[KEY]:
        return create_response(
            result=result, validation=validation, input_summary=summary,
            pass_reasons=["All %d active Duo users are enrolled in MFA and none is in bypass status." % active],
        )
    if active == 0:
        reasons = ["Duo returned %d users and none is active, so MFA enforcement covers no one." % len(users)]
    else:
        reasons = ["%d of %d active Duo users (%.1f%%) are held to MFA: %d in bypass status, %d not enrolled."
                   % (enforced, active, summary["mfaEnforcedUserPercentage"], bypass, unenrolled)]
    return create_response(
        result=result, validation=validation, input_summary=summary, fail_reasons=reasons,
        recommendations=["Take users out of bypass status and have unenrolled users complete Duo enrollment."],
    )
