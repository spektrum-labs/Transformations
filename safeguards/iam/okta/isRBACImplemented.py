# isRBACImplemented.py - Okta
#
# Method: workflow isRBACImplemented (Integration-Service), two GETs:
#   adminAssignees  GET /api/v1/iam/assignees/users?limit=200 ("List all users with role assignments"):
#                   {"value": [{"id", "orn", "_links"}], "_links": {"next"}}. Paged by _links.next.href; with
#                   reportPagination IS sets paginationStats.adminAssignees.paginationTruncated (and top-level
#                   paginationTruncated) when the list was cut off. OAuth scope okta.roles.read.
#   adminRoles      GET /api/v1/users/{id}/roles per admin, INDEX-ALIGNED with adminAssignees.value:
#                   [{"id", "label", "type", "status", "assignmentType"}]. With continueOnItemError a failed read is
#                   {"error": true, "statusCode", "item", "errorType"}; with maxItems the list stops at the cap and
#                   iterateTruncated / iterateStats.adminRoles are set. OAuth scope okta.roles.read.
# Docs: https://developer.okta.com/docs/api/openapi/okta-management/management/tag/RoleAssignmentAUser/
#   Role types: SUPER_ADMIN, ORG_ADMIN, APP_ADMIN, USER_ADMIN, HELP_DESK_ADMIN, GROUP_MEMBERSHIP_ADMIN,
#   READ_ONLY_ADMIN, MOBILE_ADMIN, API_ACCESS_MANAGEMENT_ADMIN, REPORT_ADMIN, CUSTOM, ...
#
# Replaces the generic safeguards/86ded564.../isrbacimplemented.py for Okta. That file was wired to the org factor
# list (GET /api/v1/org/factors), which says nothing about administrative roles, so it could only answer None.

KEY = "isRBACImplemented"
SUPER_ADMIN = "SUPER_ADMIN"
WRAPPERS = ["data", "response", "result", "apiResponse", "api_response", "Output"]


def transform(input):
    """
    isRBACImplemented - does the Okta org delegate administration through roles?

    True when at least one admin holds an ACTIVE role other than Super Administrator (a standard role such as
    Help Desk, App or Read-only Administrator, or a custom role): administration is split into narrower roles rather
    than every admin holding full control. One such admin read is enough, even when other reads failed.
    False when every admin's roles were read and every ACTIVE role is Super Administrator.
    Not evaluated (None, dataCollection status "error"), never False, when that cannot be shown: an error body, no
    admin list (for example okta.roles.read not granted), an empty admin list (every org has a Super
    Administrator), a role read that failed, is missing, holds no active role or is out of line with the admin
    list, or a list cut short (pagination or iteration cap).
    Output: isRBACImplemented; inputSummary carries adminCount, adminsRead, superAdminOnlyCount,
    delegatedAdminCount and roleTypeCounts. Counts only: no admin is named.
    """
    try:
        return evaluate(input)
    except Exception as e:
        return respond(None, {}, [], [], ["Transformation error: " + str(e)])


def text(value):
    return "" if value is None else str(value).strip()


def parse(value):
    import json
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    if isinstance(value, str):
        value = json.loads(value)
    for wrapper in WRAPPERS:
        if isinstance(value, dict) and wrapper in value and "adminAssignees" not in value:
            value = value[wrapper]
    return value


def error_in(block):
    if not isinstance(block, dict):
        return None
    if block.get("error") is True or block.get("vendorErrorAsResponse"):
        return "HTTP " + text(block.get("statusCode") or block.get("status_code") or "error")
    for k in ["errorCode", "errorSummary", "error", "errorMessage"]:
        if block.get(k):
            return text(block.get(k))[:120]
    return None


def truncated(data):
    if data.get("paginationTruncated") is True or data.get("iterateTruncated") is True:
        return True
    for stats_key, name in [("paginationStats", "adminAssignees"), ("iterateStats", "adminRoles")]:
        stats = data.get(stats_key)
        stats = stats.get(name) if isinstance(stats, dict) else None
        if isinstance(stats, dict):
            if stats.get("paginationTruncated") is True or stats.get("iterateTruncated") is True:
                return True
            if stats.get("itemErrors") not in (None, 0, "0", []):
                return True
    links = data.get("adminAssignees")
    links = links.get("_links") if isinstance(links, dict) else None
    nxt = links.get("next") if isinstance(links, dict) else None
    return isinstance(nxt, dict) and nxt.get("truncated") is True


def role_list(slot, admin_id):
    """ACTIVE role types for one admin, or None when the read failed or belongs to someone else."""
    for wrapper in ["apiResponse", "response", "result"]:
        if isinstance(slot, dict) and wrapper in slot:
            slot = slot[wrapper]
    if isinstance(slot, dict):
        return None
    if not isinstance(slot, list):
        return None
    types = []
    for role in slot:
        if not isinstance(role, dict):
            return None
        if text(role.get("userId")) and text(role.get("userId")) != admin_id:
            return None
        if text(role.get("status")).upper() not in ("", "ACTIVE"):
            continue
        kind = text(role.get("type")).upper()
        if not kind:
            return None
        types.append(kind)
    return types or None


def evaluate(raw):
    data = parse(raw)
    if not isinstance(data, dict):
        return respond(None, {}, [], [], ["The response is not an object with an Okta admin role assignment list"])
    problem = error_in(data)
    if problem is not None:
        return respond(None, {}, [], [], ["Okta returned an error reading admin role assignments: " + problem])
    assignees = data.get("adminAssignees")
    problem = error_in(assignees)
    if problem is not None:
        return respond(None, {}, [], [], ["Okta admin role assignment list (GET /api/v1/iam/assignees/users) could "
                                          "not be read: " + problem + "; the key needs okta.roles.read"])
    admins = assignees.get("value") if isinstance(assignees, dict) else assignees
    if not isinstance(admins, list) or not admins:
        return respond(None, {}, [], [], ["No Okta admin role assignment list was returned (every org has a Super "
                                          "Administrator), so role delegation cannot be read"])
    slots = data.get("adminRoles")
    if not isinstance(slots, list):
        return respond(None, {"adminCount": len(admins)}, [], [], ["The per-admin role reads (GET "
                                                                   "/api/v1/users/{id}/roles) were not returned"])
    cut = truncated(data) or len(slots) != len(admins)
    counts = {}
    delegated = 0
    super_only = 0
    unread = 0
    for index in range(len(admins)):
        admin = admins[index]
        admin_id = text(admin.get("id")) if isinstance(admin, dict) else ""
        types = role_list(slots[index], admin_id) if index < len(slots) and admin_id else None
        if types is None:
            unread = unread + 1
            continue
        for kind in types:
            counts[kind] = counts.get(kind, 0) + 1
        if [k for k in types if k != SUPER_ADMIN]:
            delegated = delegated + 1
        else:
            super_only = super_only + 1
    summary = {"adminCount": len(admins), "adminsRead": len(admins) - unread, "superAdminOnlyCount": super_only,
               "delegatedAdminCount": delegated, "roleTypeCounts": counts, "listComplete": not cut}
    if delegated:
        return respond(True, summary, [str(delegated) + " of " + str(len(admins)) + " Okta admin(s) hold a role "
                                       "narrower than Super Administrator (" + ", ".join(sorted(counts)) + ")"], [], [])
    if unread or cut:
        return respond(None, summary, [], [], [str(unread) + " of " + str(len(admins)) + " Okta admin role read(s) "
                                               "failed or the admin list was cut short, and no admin read so far holds "
                                               "a delegated role, so role delegation cannot be shown either way"])
    return respond(False, summary, [], ["All " + str(super_only) + " Okta admin(s) hold only Super Administrator: "
                                        "administration is not split into narrower roles"], [])


def respond(value, summary, passes, fails, errors):
    from datetime import datetime
    return {
        "transformedResponse": {KEY: value},
        "additionalInfo": {
            "dataCollection": {"status": "error" if value is None else "success",
                               "errors": errors if value is None else []},
            "validation": {"status": "success", "errors": [], "warnings": []},
            "transformation": {"status": "success", "errors": [], "inputSummary": summary},
            "evaluation": {"passReasons": passes, "failReasons": fails + (errors if value is None else []),
                           "recommendations": ["Give day-to-day administrators a standard or custom Okta admin "
                                               "role scoped to their job, and keep Super Administrator to a few "
                                               "break-glass accounts"] if value is False else [],
                           "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0",
                         "transformationId": KEY, "vendor": "Okta", "category": "Identity and Access Management"},
        },
    }
