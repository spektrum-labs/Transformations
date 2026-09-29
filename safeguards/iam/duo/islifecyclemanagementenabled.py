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
# users that do not carry the last_directory_sync field at all, proves nothing and is
# reported as a data-collection error, never judged.

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


def transform(input):
    data, validation = load(input)
    users = objects_with(data, "user_id")
    carrying = [u for u in users if "last_directory_sync" in u] if users else []
    if not carrying:
        return create_response(
            result={KEY: False, "directorySyncedUserPercentage": 0.0, "activeUsers": 0},
            validation=validation,
            api_errors=["No Duo user objects carrying last_directory_sync in the getUsers response."],
        )

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
