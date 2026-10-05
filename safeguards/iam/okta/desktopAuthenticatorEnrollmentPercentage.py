# desktopAuthenticatorEnrollmentPercentage.py - Okta (Classic and Identity Engine)
#
# Method: workflow getUserMfaPosture (Integration-Service, both Okta definitions):
#   GET /api/v1/users?filter=status eq "ACTIVE"&limit=200   -> users        (Link-header pages, reportPagination)
#   GET /api/v1/users/{userId}/factors                       -> userFactors  (one list per user, same order;
#                                                                             first 200 users; a failed user is an
#                                                                             error record in its slot)
#   iterateStats.userFactors, paginationStats.users          -> how much was read
# Docs: https://developer.okta.com/docs/api/openapi/okta-management/management/tag/UserFactor/#tag/UserFactor/operation/listFactors
#   UserFactor.factorType is one of call, email, push, question, signed_nonce, sms, token, token:hardware,
#   token:hotp, token:software:totp, u2f, web, webauthn. UserFactor.status is ACTIVE, DISABLED, ENROLLED,
#   EXPIRED, INACTIVE, NOT_SETUP or PENDING_ACTIVATION. listFactors returns the factors that the user's
#   highest-priority authenticator enrollment policy includes (Okta's note on the operation).
# Weak factors (J.J.'s ruling): sms, call (voice), email and security question. They never count as MFA here.


KEY = "desktopAuthenticatorEnrollmentPercentage"


def transform(input):
    """
    desktopAuthenticatorEnrollmentPercentage: the share of active Okta users with an ACTIVE Okta Verify enrollment on a Windows or macOS computer (a factor whose profile.platform is WINDOWS or MACOS, as Okta Verify for desktop and FastPass register).

    Computed over the users whose factors were actually read, and the result says how many that was.
    Integration-Service reads the factors of the first 200 active users in Okta's list, so a larger org
    is measured on that sample, and the coverage note says so.

    Unevaluated (value None, dataCollection status "error") when: Okta returned an error body; the
    active-user list is missing, empty or holds non-ACTIVE users; the fan-out counts are missing or do not
    line up with the users; no user's factors could be read, or more than 10% could not; or the
    transformation errors. None of these is a measurement, so none may read as Passed or Failed.

    Does not prove: that the desktop enrollment is used to sign in, or that it covers every computer the user has.
    """
    try:
        state = read_users(input)
    except Exception as e:
        return unevaluated("Transformation error: " + str(e), [str(e)])
    if state["error"] is not None:
        return unevaluated(state["error"], [])
    try:
        flags = [counts(r["factors"]) for r in state["read"]]
    except Exception as e:
        return unevaluated("Transformation error: " + str(e), [str(e)])
    matched = [state["read"][i] for i in range(len(flags)) if flags[i]]
    missing = [state["read"][i] for i in range(len(flags)) if not flags[i]]
    total = len(state["read"])
    value = round(100.0 * len(matched) / total, 1)
    line = (str(len(matched)) + " of " + str(total) + " users read (" + str(value) + "%) " + "have Okta Verify active on a Windows or macOS computer" + ". " +
            coverage(state))
    passes = [line] if not missing else []
    fails = [] if not missing else [line + ". Without: " + names(missing)]
    summary = coverage_summary(state)
    summary["usersMatched"] = len(matched)
    return respond(value, passes, fails, summary, [] if not missing else ["Roll out Okta Verify for Windows and macOS and have users enroll it (Okta FastPass)"])


def counts(factors):
    return len([f for f in factors if active(f)
                and text(as_dict(f.get("profile")).get("platform")).upper() in DESKTOP_PLATFORMS]) > 0


WEAK = ["sms", "call", "email", "question"]
STRONG = ["push", "signed_nonce", "token", "token:hardware", "token:hotp", "token:software:totp", "u2f", "web", "webauthn"]
DESKTOP_PLATFORMS = ["WINDOWS", "MACOS"]
MAX_UNREAD_SHARE = 0.1


def text(value):
    if value is None:
        return ""
    return str(value).strip()


def as_dict(value):
    return value if isinstance(value, dict) else {}


def parse(value):
    import json
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    if isinstance(value, str):
        value = json.loads(value)
    for wrapper in ["data", "response", "result", "apiResponse", "_response_data"]:
        if isinstance(value, dict) and wrapper in value and LIST_KEY not in value:
            value = value[wrapper]
    return value


def error_in(data):
    if not isinstance(data, dict):
        return "Response is not the Okta per-user MFA read"
    for k in ["errorCode", "errorSummary", "error", "errors", "errorMessage"]:
        if data.get(k):
            return "Okta returned an error: " + text(data.get(k))[:200]
    for k in ["statusCode", "status_code"]:
        if data.get(k) not in (None, 200):
            return "Okta returned HTTP " + text(data.get(k))
    return None


def item_list(item):
    """A list of objects, or None when the slot is an error record or unreadable."""
    if isinstance(item, dict):
        if item.get("error") is True:
            return None
        for k in ["errorCode", "errorSummary", "errors", "errorMessage"]:
            if item.get(k):
                return None
        for wrapper in ["apiResponse", "response", "result", "data"]:
            if wrapper in item:
                return item_list(item[wrapper])
        return None
    if isinstance(item, list):
        if [x for x in item if not isinstance(x, dict)]:
            return None
        return item
    return None


def factor_type(factor):
    return text(factor.get("factorType")).lower()


def active(factor):
    return text(factor.get("status")).upper() == "ACTIVE"


def strong_active(factors):
    return [f for f in factors if active(f) and factor_type(f) in STRONG]


def whole(value):
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def fan_out(data, list_key, stats_key, count):
    """Read one iterate step's aligned per-item lists. Returns (lists_or_None_per_item, error)."""
    stats = as_dict(as_dict(data.get("iterateStats")).get(stats_key))
    total = stats.get("itemsTotal")
    processed = stats.get("itemsProcessed")
    if not whole(total) or not whole(processed):
        return None, "The read carries no fan-out counts (iterateStats." + stats_key + "), so its coverage is unknown"
    if total != count:
        return None, "The fan-out counted " + str(total) + " items but " + str(count) + " were listed"
    lists = data.get(list_key)
    if not isinstance(lists, list) or len(lists) != processed or processed > count:
        return None, "The " + list_key + " lists do not line up with the items they were read for"
    return [item_list(x) for x in lists], None


LIST_KEY = "users"


def read_users(raw):
    """Users actually read, with coverage. state["error"] is set when the read cannot answer."""
    state = {"error": None, "read": [], "listed": 0, "attempted": 0, "unread": 0, "listComplete": None,
             "sampled": True}
    data = parse(raw)
    problem = error_in(data)
    if problem is not None:
        state["error"] = problem
        return state
    users = data.get("users")
    if not isinstance(users, list) or [u for u in users if not isinstance(u, dict)]:
        state["error"] = "The active-user list is missing or unreadable"
        return state
    if not users:
        state["error"] = "Okta returned no active users, so the user list was not read"
        return state
    if [u for u in users if text(u.get("status")).upper() != "ACTIVE"]:
        state["error"] = "The user list holds users that are not ACTIVE, so it is not the active-user read"
        return state
    page = as_dict(as_dict(data.get("paginationStats")).get("users"))
    if page.get("paginationTruncated") is True or data.get("paginationTruncated") is True:
        state["listComplete"] = False
    elif page.get("paginationTruncated") is False:
        state["listComplete"] = True
    lists, problem = fan_out(data, "userFactors", "userFactors", len(users))
    if problem is not None:
        state["error"] = problem
        return state
    read = []
    for index in range(len(lists)):
        if lists[index] is not None:
            read.append({"user": users[index], "factors": lists[index]})
    state["listed"] = len(users)
    state["attempted"] = len(lists)
    state["unread"] = len(lists) - len(read)
    state["read"] = read
    if not read:
        state["error"] = "No user's factors could be read (" + str(len(lists)) + " tried)"
        return state
    if state["unread"] > MAX_UNREAD_SHARE * len(lists):
        state["error"] = ("The factors of " + str(state["unread"]) + " of " + str(len(lists)) +
                          " users could not be read, more than 10%, so the sample is not reliable")
        return state
    state["sampled"] = not (state["listComplete"] is True and state["attempted"] == len(users) and state["unread"] == 0)
    return state


def coverage(state):
    listed = str(state["listed"]) + ("" if state["listComplete"] is True else " or more")
    note = ("Read the factors of " + str(len(state["read"])) + " of " + listed + " active Okta users")
    if state["unread"]:
        note = note + " (" + str(state["unread"]) + " could not be read)"
    if state["sampled"]:
        note = note + "; the first users in Okta's list, not every user"
    return note


def coverage_summary(state):
    return {"activeUsersListed": state["listed"], "userListComplete": state["listComplete"],
            "usersRead": len(state["read"]), "usersNotRead": state["unread"],
            "usersNotAttempted": state["listed"] - state["attempted"], "sampled": state["sampled"]}


def label(user):
    profile = as_dict(user.get("profile"))
    return text(profile.get("login")) or text(user.get("id")) or "(unnamed)"


def names(rows, limit=10):
    shown = [label(r["user"]) for r in rows[:limit]]
    more = len(rows) - len(shown)
    return ", ".join(shown) + (" and " + str(more) + " more" if more > 0 else "")


def respond(value, passes, fails, summary, recommendations):
    from datetime import datetime
    return {
        "transformedResponse": {KEY: value},
        "additionalInfo": {
            "dataCollection": {"status": "success", "errors": []},
            "validation": {"status": "success", "errors": [], "warnings": []},
            "transformation": {"status": "success", "errors": [], "inputSummary": summary},
            "evaluation": {"passReasons": passes, "failReasons": fails, "recommendations": recommendations,
                           "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0",
                         "transformationId": KEY, "vendor": "Okta", "category": "Identity"},
        },
    }


def unevaluated(reason, errors):
    """None with dataCollection status "error": the only None Token-Service grades as not evaluated."""
    from datetime import datetime
    return {
        "transformedResponse": {KEY: None},
        "additionalInfo": {
            "dataCollection": {"status": "error", "errors": [reason]},
            "validation": {"status": "error" if errors else "unknown", "errors": [], "warnings": []},
            "transformation": {"status": "error" if errors else "success", "errors": errors, "inputSummary": {}},
            "evaluation": {"passReasons": [], "failReasons": [reason], "recommendations": [], "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0",
                         "transformationId": KEY, "vendor": "Okta", "category": "Identity"},
        },
    }
