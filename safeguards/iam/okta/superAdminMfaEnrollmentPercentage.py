# superAdminMfaEnrollmentPercentage.py - Okta (Classic and Identity Engine)
#
# Method: workflow getAdminMfaPosture (Integration-Service, both Okta definitions):
#   GET /api/v1/iam/assignees/users              -> roleAssignees {value: [...], _links}  (body-link pages)
#   GET /api/v1/users/{userId}/roles             -> assigneeRoles    (one list per assignee, same order)
#   GET /api/v1/users/{userId}/factors           -> assigneeFactors  (one list per assignee, same order)
#   first 100 assignees; a failed read is an error record in its slot
# Docs: https://developer.okta.com/docs/api/openapi/okta-management/management/tag/RoleAssignmentAUser/
#   listUsersWithRoleAssignments -> {value: [{id, orn, _links}], _links: {next}}; listAssignedRolesForUser ->
#   [{type, status, assignmentType}], type SUPER_ADMIN is the super administrator role.
#   https://developer.okta.com/docs/api/openapi/okta-management/management/tag/UserFactor/#tag/UserFactor/operation/listFactors
# Weak factors (J.J.'s ruling): sms, call (voice), email and security question. They never count as MFA here.


KEY = "superAdminMfaEnrollmentPercentage"
LIST_KEY = "roleAssignees"
SUPER_ADMIN = "SUPER_ADMIN"


def transform(input):
    """
    superAdminMfaEnrollmentPercentage: the share of Okta super administrators (role type SUPER_ADMIN) who
    have at least one ACTIVE strong MFA factor (push, Okta FastPass, TOTP or hardware token, FIDO U2F or
    WebAuthn, Duo or another token). SMS, voice, email and security question do not count.

    Every role assignee is read, so this is not a sample: it is reported only when the assignee list is
    complete (at most 100 assignees, every page read) and every assignee's roles were read, and every super
    administrator's factors were read.

    Unevaluated (value None, dataCollection status "error") when: Okta returned an error body (a 403 here
    usually means the Okta - Application service app was not granted okta.roles.read); the assignee list is
    missing, cut off or has unread pages; the fan-out counts are missing, capped or do not line up; any
    assignee's roles or any super administrator's factors could not be read; no super administrator was
    found (every Okta org has one, so none found means the roles were not readable); or the transformation
    errors. None of these is a measurement, so none may read as Passed or Failed.

    Does not prove: that a sign-on policy requires those factors from administrators.
    """
    try:
        state = evaluate(input)
    except Exception as e:
        return unevaluated("Transformation error: " + str(e), [str(e)])
    if state["error"] is not None:
        return unevaluated(state["error"], [])
    admins = state["admins"]
    enrolled = [a for a in admins if strong_active(a["factors"])]
    missing = [a for a in admins if not strong_active(a["factors"])]
    value = round(100.0 * len(enrolled) / len(admins), 1)
    line = (str(len(enrolled)) + " of " + str(len(admins)) + " Okta super administrators (" + str(value) +
            "%) have an active strong MFA factor (not SMS, voice, email or security question)")
    passes = [line] if not missing else []
    fails = [] if not missing else [line + ". Without one: " + ", ".join([a["id"] for a in missing][:10])]
    summary = {"roleAssignees": state["assignees"], "superAdmins": len(admins), "superAdminsEnrolled": len(enrolled)}
    return respond(value, passes, fails, summary, [] if not missing else
                   ["Enroll every super administrator in a strong factor (Okta FastPass, WebAuthn/FIDO2 or a hardware token) and remove SMS, voice, email and security question from their options"])


def evaluate(raw):
    state = {"error": None, "admins": [], "assignees": 0}
    data = parse(raw)
    problem = error_in(data)
    if problem is not None:
        state["error"] = problem
        return state
    page = as_dict(data.get("roleAssignees"))
    problem = error_in(page)
    if problem is not None:
        state["error"] = problem
        return state
    assignees = page.get("value")
    if not isinstance(assignees, list) or [a for a in assignees if not isinstance(a, dict)]:
        state["error"] = "The role-assignee list is missing or unreadable"
        return state
    if not assignees:
        state["error"] = "Okta listed no users with admin roles, so the role assignments were not read"
        return state
    nxt = as_dict(as_dict(page.get("_links")).get("next"))
    stats = as_dict(as_dict(data.get("paginationStats")).get("roleAssignees"))
    if text(nxt.get("href")) or nxt.get("truncated") is True or stats.get("paginationTruncated") is True \
            or data.get("paginationTruncated") is True:
        state["error"] = "The role-assignee list was cut off, so a super administrator could be missing"
        return state
    if data.get("iterateTruncated") is True:
        state["error"] = "More role assignees than Integration-Service reads per evaluation (100)"
        return state
    roles, problem = fan_out(data, "assigneeRoles", "assigneeRoles", len(assignees))
    if problem is not None:
        state["error"] = problem
        return state
    factors, problem = fan_out(data, "assigneeFactors", "assigneeFactors", len(assignees))
    if problem is not None:
        state["error"] = problem
        return state
    if len(roles) != len(assignees) or len(factors) != len(assignees):
        state["error"] = "Not every role assignee was read"
        return state
    if [r for r in roles if r is None]:
        state["error"] = "The roles of " + str(len([r for r in roles if r is None])) + " role assignees could not be read"
        return state
    admins = []
    for index in range(len(assignees)):
        types = [text(r.get("type")).upper() for r in roles[index]
                 if text(r.get("status")).upper() in ("", "ACTIVE")]
        if SUPER_ADMIN in types:
            if factors[index] is None:
                state["error"] = "A super administrator's factors could not be read"
                return state
            admins.append({"id": text(assignees[index].get("id")) or "(unnamed)", "factors": factors[index]})
    if not admins:
        state["error"] = "No super administrator was found among " + str(len(assignees)) + " role assignees"
        return state
    state["admins"] = admins
    state["assignees"] = len(assignees)
    return state


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
