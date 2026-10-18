import json
from datetime import datetime

# isLifeCycleManagementEnabled -- are Duo users provisioned and deprovisioned from a
# directory rather than by hand?
#
# Source: GET /admin/v1/users (method getUsers, returnSpec {"response": [...]}). Duo sets
# last_directory_sync (Unix time) on every user a directory sync (Active Directory,
# Entra ID, OpenLDAP, Google Workspace) created or updated, and null on hand-made users.
#
# Verdict: true when at least one active user is managed by directory sync.
# directorySyncedUserPercentage is the measure. A body with no user object (user_id), or
# users that do not carry the last_directory_sync field at all, proves nothing (an error
# collapses to the returnSpec default []), so it is Unevaluated (every key None, data-collection
# error), never judged and never False: an empty, error or non-list body, an exception, Duo's 403 / 40301
# refusal (names "Grant resource - Read", the Admin API permission Duo documents for GET /admin/v1/users)
# and any other handed-over vendor error (vendorErrorAsResponse). A real read still measures: users came
# back carrying last_directory_sync and none was synced is a measured False with 0.0.

KEY = "isLifeCycleManagementEnabled"


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


# Integration-Service hands a vendor refusal over as data when the method opts in
# (vendorErrorAsResponse): {"vendorErrorAsResponse": {"status": 403, "bodyContains": ..., "body": <vendor body>}}.
# Duo answers a missing Admin API permission with HTTP 403 {"stat": "FAIL", "code": 40301,
# "message": "Access forbidden"}; GET /admin/v1/users needs "Grant resource - Read" (Duo Admin API docs). That says
# nothing about the tenant's posture, so every key stays None (Unevaluated) and the error names the
# permission to grant. Any other handed-over refusal is Unevaluated with errorCode "vendor_refusal" and names
# no permission.
REFUSAL_FORBIDDEN_CODE = 40301
PERMISSION_NOT_GRANTED = "permission_not_granted"
VENDOR_REFUSAL = "vendor_refusal"
REQUIRED_PERMISSION = "Grant resource - Read"
REFUSAL_KEYS = ["isLifeCycleManagementEnabled", "usersReturned", "activeUsers",
                "directorySyncedUsers", "directorySyncedUserPercentage", "manuallyManagedUsers"]
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


def refusal_unevaluated(envelope, validation=None):
    """Duo's refusal (or any other handed-over vendor error) as Unevaluated: every key None, never False."""
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
    out = create_response(result, validation, fail_reasons=[problem], api_errors=[problem],
                          recommendations=[recommendation])
    collection = out["additionalInfo"]["dataCollection"]
    if forbidden:
        collection["errorCode"] = PERMISSION_NOT_GRANTED
        collection["requiredPermission"] = REQUIRED_PERMISSION
    else:
        collection["errorCode"] = VENDOR_REFUSAL
    return out


def unreadable(reason, validation=None):
    """Nothing was measured: every key None, never False or 0."""
    result = {}
    for k in REFUSAL_KEYS:
        result[k] = None
    problem = ("No Duo user objects (user_id) carrying last_directory_sync could be read from the getUsers response (" + reason
               + "). An empty or failed read cannot show whether users are provisioned from a directory, so this is not a posture result.")
    return create_response(
        result=result, validation=validation, api_errors=[problem], fail_reasons=[problem],
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
    if not isinstance(validation, dict):
        validation = None
    users = objects_with(data, "user_id")
    if users is None:
        return unreadable("empty, error or unrecognised body")
    carrying = [u for u in users if "last_directory_sync" in u]
    if not carrying:
        return unreadable("no user object carries last_directory_sync")

    active = 0
    synced = 0
    for u in carrying:
        if str(u.get("status") or "").lower() in INACTIVE_STATUSES:
            continue
        active = active + 1
        if u.get("last_directory_sync") not in (None, "", 0):
            synced = synced + 1

    summary = {
        "usersReturned": len(users),
        "activeUsers": active,
        "directorySyncedUsers": synced,
        "directorySyncedUserPercentage": pct(synced, active),
        "manuallyManagedUsers": active - synced,
    }
    result = {KEY: synced > 0}
    result.update(summary)

    if result[KEY]:
        return create_response(
            result=result, validation=validation, input_summary=summary,
            pass_reasons=["%d of %d active Duo users (%.1f%%) are provisioned by directory sync "
                          "(last_directory_sync set)." % (synced, active, summary["directorySyncedUserPercentage"])],
        )
    return create_response(
        result=result, validation=validation, input_summary=summary,
        fail_reasons=["None of the %d active Duo users was created or updated by a directory sync "
                      "(last_directory_sync is null on all), so joiners and leavers are managed by hand." % active],
        recommendations=["Configure Duo directory sync from the identity source (Active Directory, Entra ID, "
                         "Google Workspace) so users are provisioned and removed automatically."],
    )
