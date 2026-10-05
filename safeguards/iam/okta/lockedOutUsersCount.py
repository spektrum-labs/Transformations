# lockedOutUsersCount.py - Okta (Identity Engine and Classic)
#
# Method: getUserAccounts (Integration-Service) -> GET {$oktaDomain}/api/v1/users
# Docs: https://developer.okta.com/docs/api/openapi/okta-management/management/tag/User/#tag/User/operation/listUsers
#   Without a search or filter, listUsers returns every user except DEPROVISIONED ones, one page at a time
#   (Link header, rel="next"). User.status is one of STAGED, PROVISIONED, ACTIVE, RECOVERY,
#   PASSWORD_EXPIRED, LOCKED_OUT, SUSPENDED or DEPROVISIONED.


def transform(input):
    """
    lockedOutUsersCount: the number of Okta users whose status is LOCKED_OUT. Lower is better. A locked-out account has hit Okta's lockout threshold, often from repeated failed sign-ins.

    Counted from the full user list. The count names up to 10 of the accounts.

    Unevaluated (value None, dataCollection status "error") when: Okta returned an error body; the body is
    not a list of users; the list is empty (an org always has at least the admin who issued the API
    token); a user entry has no status; the read is marked cut off (paginationTruncated); the list length
    is a whole multiple of 200 (the page size, so pages may be missing); or the transformation errors.
    None of these is a measurement, so none may read as Passed or Failed.

    Does not prove: why an account is locked out, or whether it belongs to a person or a service.
    """
    try:
        state = evaluate(input)
    except Exception as e:
        return unevaluated("Transformation error: " + str(e), [str(e)])
    if state["error"] is not None:
        return unevaluated(state["error"], [])
    count = len(state["matched"])
    passes = []
    fails = []
    summary = str(count) + " of " + str(state["total"]) + " Okta users are locked out"
    if count == 0:
        passes.append(summary)
    else:
        fails.append(summary + ": " + ", ".join(state["matched"][:10]) + (" and " + str(count - 10) + " more" if count > 10 else ""))
    return respond(count, passes, fails, {"usersRead": state["total"], "lockedoutUsers": count})


PAGE = 200
STATUS = "LOCKED_OUT"
STATUSES = ["STAGED", "PROVISIONED", "ACTIVE", "RECOVERY", "PASSWORD_EXPIRED", "LOCKED_OUT", "SUSPENDED", "DEPROVISIONED"]


def text(value):
    if value is None:
        return ""
    return str(value).strip()


def truthy(value):
    if isinstance(value, bool):
        return value
    return text(value).lower() == "true"


def truncated(value):
    if isinstance(value, dict):
        if truthy(value.get("paginationTruncated")):
            return True
        return truncated(value.get("response_metadata"))
    return False


def parse(value):
    import json
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    if isinstance(value, str):
        value = json.loads(value)
    for step in range(4):
        if not isinstance(value, dict):
            break
        moved = False
        for wrapper in ["data", "response", "result", "apiResponse", "_response_data", "users"]:
            if wrapper in value and isinstance(value[wrapper], (list, dict)):
                value = value[wrapper]
                moved = True
                break
        if not moved:
            break
    return value


def error_in(data):
    if isinstance(data, dict):
        for k in ["errorCode", "errorSummary", "error", "errors", "errorMessage"]:
            if data.get(k):
                return "Okta returned an error: " + text(data.get(k))[:200]
        return "Response is not a list of Okta users"
    if not isinstance(data, list):
        return "Response is not a list of Okta users"
    return None


def label(user):
    profile = user.get("profile") if isinstance(user.get("profile"), dict) else {}
    return text(profile.get("login")) or text(user.get("id")) or "(unnamed)"


def evaluate(raw):
    state = {"error": None, "matched": [], "total": 0}
    if truncated(raw if isinstance(raw, dict) else None):
        state["error"] = "Okta's user read was cut off (paginationTruncated)"
        return state
    data = parse(raw)
    problem = error_in(data)
    if problem is not None:
        state["error"] = problem
        return state
    users = [u for u in data if isinstance(u, dict)]
    if len(users) != len(data):
        state["error"] = "The user list holds entries that are not user objects"
        return state
    if not users:
        state["error"] = "Okta returned no users, so the user list was not read"
        return state
    if len(users) % PAGE == 0:
        state["error"] = ("Okta returned " + str(len(users)) + " users, a whole number of pages, so the list may be cut off")
        return state
    for user in users:
        status = text(user.get("status")).upper()
        if status not in STATUSES:
            state["error"] = "A user entry has no recognised status"
            return state
        if status == STATUS:
            state["matched"].append(label(user))
    state["total"] = len(users)
    return state


def respond(count, passes, fails, summary):
    from datetime import datetime
    return {
        "transformedResponse": {"lockedOutUsersCount": count},
        "additionalInfo": {
            "dataCollection": {"status": "success", "errors": []},
            "validation": {"status": "success", "errors": [], "warnings": []},
            "transformation": {"status": "success", "errors": [], "inputSummary": summary},
            "evaluation": {"passReasons": passes, "failReasons": fails, "recommendations": [] if count == 0 else
                           ["Review each locked-out account: unlock it after confirming the owner, or deactivate it if it is no longer needed"],
                           "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0",
                         "transformationId": "lockedOutUsersCount", "vendor": "Okta", "category": "Identity"},
        },
    }


def unevaluated(reason, errors):
    from datetime import datetime
    return {
        "transformedResponse": {"lockedOutUsersCount": None},
        "additionalInfo": {
            "dataCollection": {"status": "error", "errors": [reason]},
            "validation": {"status": "error" if errors else "unknown", "errors": [], "warnings": []},
            "transformation": {"status": "error" if errors else "success", "errors": errors, "inputSummary": {}},
            "evaluation": {"passReasons": [], "failReasons": [reason], "recommendations": [], "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0",
                         "transformationId": "lockedOutUsersCount", "vendor": "Okta", "category": "Identity"},
        },
    }
