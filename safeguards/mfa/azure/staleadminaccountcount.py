"""
Transformation: staleAdminAccountCount
Vendor: Microsoft Entra ID (Azure AD app registration and Azure AD One-Click)  |  Category: Identity / Admin Accounts

Method: workflow getStaleAdminAccounts (Integration-Service), two steps, each with output.key and merge: true,
so this transform receives {"roleAssignments": <body>, "users": <body>}:
  roleAssignments <- getDirectoryRoleAssignments: GET /v1.0/roleManagement/directory/roleAssignments
                     ?$expand=principal($select=id), @odata.nextLink paging. Body {"value": [{"principalId",
                     "roleDefinitionId", "principal": {"@odata.type", "id"}}, ...]}. ACTIVE assignments only.
  users           <- getUserSignInActivity: GET /v1.0/users?$select=id,userPrincipalName,displayName,accountEnabled,
                     userType,createdDateTime,signInActivity&$top=120, @odata.nextLink paging. signInActivity
                     needs an Entra ID P1 or P2 licence; without one Graph answers HTTP 403, which the method hands
                     over as a vendorErrorAsResponse marker.

staleAdminAccountCount = the number of ENABLED active role holders with no successful sign-in in the last
STALE_DAYS (90) days:
  * an admin is a USER that is the principal of an active directory role assignment (any directory role, any
    scope). Service principals holding a role are not users and are not counted (their number is in inputSummary);
  * GROUP-HELD assignments (principal @odata.type #microsoft.graph.group): role-assignable group members are not
    expanded, so they could hide a stale admin. With any group-held assignment, a user-level count of 0 is
    Unevaluated ("N role assignments are through groups; members not checked"), never a pass; a count above 0 is
    still a fail with the accounts found, and the first reason adds that N group-held assignments were not
    expanded. inputSummary.groupRoleAssignmentCount carries N. A principal with no @odata.type that is not in the
    user list is Unevaluated (type cannot be told), never a pass;
  * enabled = accountEnabled true; disabled role holders are not counted and are listed in
    inputSummary.disabledAdmins;
  * last sign-in = signInActivity.lastSuccessfulSignInDateTime; when it is absent, the later of
    lastSignInDateTime and lastNonInteractiveSignInDateTime;
  * stale = that sign-in older than 90 days, or no sign-in at all and createdDateTime more than 90 days ago.
The requirement reads lessThan "0" (Token-Service: <= 0), so the check passes only at 0.
"Now" is one datetime.now(timezone.utc) read per evaluation (utc_now), reported as inputSummary.evaluatedAt.

Not covered: PIM-ELIGIBLE role holders (roleEligibilityScheduleInstances) are not read, so the scope is "active
role holders". Entra speaks only for Entra role holders; the first reason names the tool and that scope and at
most 20 accounts, then "and N more"; inputSummary.affectedAccounts carries at most 50, with the full count in
affectedAccountCount (same shape as legacyauthblocked.py, #891).

Unevaluated (every key None, dataCollection status "error"), never a pass, on: an error body; a vendorErrorAsResponse
marker (403 Authorization_RequestDenied: the app lacks a permission; 403 naming a premium licence: the tenant has
no Entra ID P1; 400, 429, 5xx); a missing or unrecognised assignment or user list; an empty user list; a read
that was not finished (paginationTruncated / truncated set, or @odata.nextLink remaining); a user role holder
missing from the user list (a partial read); a role holder that cannot be told to be a user or not; a user with
no readable accountEnabled; a read with no signInActivity at all; an unparseable sign-in or creation date, or a
never-signed-in admin with no createdDateTime; no enabled role holder at all; any exception.

This file is byte-identical to safeguards/d9b6f27a-2e67-4b55-a09e-0784c5de9abd/staleadminaccountcount.py
(test_entra_stale_admin_account_count.py enforces it).
"""

import json
from datetime import datetime, timezone

KEY = "staleAdminAccountCount"
TOOL = "Microsoft Entra ID"
STALE_DAYS = 90
MAX_NAMED = 20
MAX_AFFECTED = 50
MAX_NAME_LEN = 100
SECTIONS = ["roleAssignments", "users"]
ENDPOINTS = {
    "roleAssignments": "GET /v1.0/roleManagement/directory/roleAssignments",
    "users": "GET /v1.0/users (signInActivity)",
}
USER_TYPE = "#microsoft.graph.user"
NON_USER_TYPES = ["#microsoft.graph.serviceprincipal", "#microsoft.graph.group", "#microsoft.graph.device"]
NOT_COVERED = ("Not covered: PIM-eligible role holders (not active) and members of role-assignable groups are "
               "not read; only users with an active directory role assignment are judged.")


# ---------------------------------------------------------------- shared helpers (same in the Duo and Entra files)

def utc_now():
    return datetime.now(timezone.utc)


def create_response(result, pass_reasons=None, fail_reasons=None, recommendations=None, input_summary=None,
                    api_errors=None, transformation_errors=None, additional_findings=None):
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if api_errors else "success", "errors": api_errors or []},
            "validation": {"status": "unknown", "errors": [], "warnings": []},
            "transformation": {
                "status": "error" if transformation_errors else "success",
                "errors": transformation_errors or [],
                "inputSummary": input_summary or {},
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or [],
            },
            "metadata": {
                "evaluatedAt": datetime.now(timezone.utc).isoformat(),
                "schemaVersion": "2.0",
                "transformationId": KEY,
                "vendor": TOOL,
                "category": "Identity",
            },
        },
    }


def empty_result():
    return {KEY: None, "adminCount": None}


def unevaluated(reason, summary=None, transformation_errors=None):
    """Nothing was measured: every key None, never 0."""
    text = str(reason)[:500]
    return create_response(empty_result(), fail_reasons=["Not evaluated: " + text], api_errors=[text],
                           input_summary=summary, transformation_errors=transformation_errors)


def decode(raw):
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    if isinstance(raw, str):
        if raw.strip() == "":
            return None
        return json.loads(raw)
    return raw


def text_of(value):
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        try:
            return json.dumps(value)
        except Exception:
            return str(value)
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def flag_set(value):
    if value is True:
        return True
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value != 0
    return str(value).strip().lower() in ("true", "1", "yes")


def marker_of(value):
    """Integration-Service's vendorErrorAsResponse marker dict, or None."""
    if isinstance(value, dict) and "vendorErrorAsResponse" in value:
        marker = value.get("vendorErrorAsResponse")
        return marker if isinstance(marker, dict) else {"status": None, "body": marker}
    return None


def status_code_of(value):
    if not isinstance(value, dict):
        return None
    for k in ("statusCode", "status_code"):
        code = value.get(k)
        if isinstance(code, bool):
            continue
        if isinstance(code, int):
            return code
        if isinstance(code, str) and code.strip().isdigit():
            return int(code.strip())
    return None


def link_text(value):
    """A next-page link as text, '' when there is none."""
    text = str(value or "").strip()
    return "" if text in ("None", "null") else text


def truncation_text(value, label):
    """Why a read is not complete, '' when nothing says so. Integration-Service marks a read it stopped early with
    paginationTruncated (envelope or response_metadata) or <pagination block>.truncated, and leaves an unread next
    link in the body."""
    if not isinstance(value, dict):
        return ""
    blocks = [value]
    for k in ("response_metadata", "metadata", "pagination"):
        if isinstance(value.get(k), dict):
            blocks.append(value[k])
    links = value.get("_links")
    if isinstance(links, dict) and isinstance(links.get("next"), dict):
        nxt = links["next"]
        blocks.append(nxt)
        if link_text(nxt.get("href")):
            return label + " was not read to the end (a next page link remains)"
    for block in blocks:
        for k in ("paginationTruncated", "truncated"):
            if k in block and flag_set(block.get(k)):
                return label + " was not read to the end (" + k + " is set)"
    if link_text(value.get("@odata.nextLink")):
        return label + " was not read to the end (@odata.nextLink remains)"
    return ""


def parse_time(value):
    """A UTC datetime from ISO 8601 text or unix seconds, else None. fromisoformat only: strptime imports _strptime,
    which the sandbox refuses."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        if value <= 0:
            return None
        try:
            return datetime.fromtimestamp(value, timezone.utc)
        except Exception:
            return None
    raw = str(value).strip()
    if raw.isdigit():
        return parse_time(int(raw))
    if len(raw) < 10:
        return None
    if len(raw) > 10 and raw[10] == " ":
        raw = raw[:10] + "T" + raw[11:]
    if raw.endswith("Z") or raw.endswith("z"):
        raw = raw[:-1] + "+00:00"
    tee = raw.find("T")
    dot = raw.find(".", tee) if tee >= 0 else -1
    if dot >= 0:
        end = dot + 1
        while end < len(raw) and raw[end].isdigit():
            end += 1
        digits = raw[dot + 1:end]
        if not digits:
            return None
        raw = raw[:dot + 1] + (digits + "000000")[:6] + raw[end:]
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def older_than_window(moment, now):
    return (now - moment).total_seconds() > STALE_DAYS * 86400


def clip(value):
    return str(value).strip()[:MAX_NAME_LEN]


def name_list(items):
    """At most MAX_NAMED identifiers, then 'and N more'."""
    shown = ", ".join(items[:MAX_NAMED])
    if len(items) > MAX_NAMED:
        shown = shown + " and " + str(len(items) - MAX_NAMED) + " more"
    return shown


def finish(stale, enabled_count, never_count, disabled, extra_summary, now, scope_line, recommendations,
           not_covered=None):
    """The measured answer: count, scoped first reason, capped account lists."""
    stale = sorted(stale)
    disabled = sorted(disabled)
    summary = {
        "adminCount": enabled_count,
        "affectedAccounts": stale[:MAX_AFFECTED],
        "affectedAccountCount": len(stale),
        "neverSignedInAdminCount": never_count,
        "disabledAdmins": disabled[:MAX_AFFECTED],
        "disabledAdminCount": len(disabled),
        "staleAfterDays": STALE_DAYS,
        "evaluatedAt": now.isoformat(),
    }
    for k in extra_summary:
        summary[k] = extra_summary[k]
    line = scope_line % (len(stale), enabled_count)
    findings = []
    if disabled:
        findings.append(TOOL + ": " + str(len(disabled)) + " disabled admin account(s) are not counted: "
                        + name_list(disabled))
    tail = [not_covered] if not_covered else []
    result = {KEY: len(stale), "adminCount": enabled_count}
    if stale:
        return create_response(result, fail_reasons=[line + ": " + name_list(stale)] + tail,
                               recommendations=recommendations, input_summary=summary,
                               additional_findings=findings)
    return create_response(result, pass_reasons=[line + "; every enabled admin signed in within the last "
                                                 + str(STALE_DAYS) + " days"] + tail,
                           input_summary=summary, additional_findings=findings)


# ---------------------------------------------------------------- Microsoft Entra ID

def unwrap(value):
    for _ in range(4):
        if not isinstance(value, dict) or "roleAssignments" in value or "users" in value:
            return value
        moved = False
        for k in ("data", "apiResponse", "response", "result", "Output", "_response_data"):
            if isinstance(value.get(k), dict):
                value = value[k]
                moved = True
                break
        if not moved:
            return value
    return value


def marker_problem(marker, endpoint):
    status = marker.get("status")
    body = text_of(marker.get("body"))
    low = body.lower()
    if status == 403 and ("premium" in low or "licen" in low):
        return ("needs Entra ID P1: Microsoft Graph refused " + endpoint + " with HTTP 403 because sign-in "
                "activity needs an Entra ID P1 or P2 licence, which this tenant does not have; nothing was measured")
    if status == 403 and "authorization_requestdenied" in low:
        return ("Microsoft Graph refused " + endpoint + " with HTTP 403 (Authorization_RequestDenied): the app "
                "registration lacks a permission this read needs (User.Read.All and AuditLog.Read.All for sign-in "
                "activity, RoleManagement.Read.Directory for role assignments); nothing was measured")
    if status == 400:
        return "Microsoft Graph rejected " + endpoint + " (HTTP 400): " + body[:200]
    if status == 429:
        return "Microsoft Graph throttled " + endpoint + " (HTTP 429); nothing was measured"
    return "Microsoft Graph refused " + endpoint + " (HTTP " + str(status)[:10] + "); nothing was measured"


def is_page_list(body):
    """A list of Graph pages ({"value": [...]}) rather than a list of objects."""
    return (isinstance(body, list) and len(body) > 0
            and all(isinstance(p, dict) and ("value" in p or "error" in p or "vendorErrorAsResponse" in p)
                    for p in body))


def section_problem(name, body):
    """Why a section cannot be read as evidence, '' when it can. A body may be one page or a list of pages."""
    if is_page_list(body):
        for page in body:
            problem = page_problem(name, page)
            if problem:
                return problem
        return ""
    return page_problem(name, body)


def page_problem(name, body):
    endpoint = ENDPOINTS[name]
    marker = marker_of(body)
    if marker is not None:
        return marker_problem(marker, endpoint)
    if isinstance(body, dict):
        error = body.get("error")
        if error:
            if isinstance(error, dict):
                return ("Microsoft Graph returned an error for " + endpoint + ": "
                        + text_of(error.get("code"))[:80] + " " + text_of(error.get("message"))[:200]).strip()
            return "Microsoft Graph returned an error for " + endpoint + ": " + text_of(body.get("message") or error)[:200]
        code = status_code_of(body)
        if code is not None and code >= 400:
            return "Microsoft Graph answered " + endpoint + " with HTTP " + str(code)
        return truncation_text(body, endpoint)
    return ""


def items_of(body):
    if is_page_list(body):
        items = []
        for page in body:
            if not isinstance(page.get("value"), list):
                return None
            items.extend(page["value"])
        return items
    if isinstance(body, list):
        return body
    if isinstance(body, dict) and isinstance(body.get("value"), list):
        return body["value"]
    return None


def user_name(user, fallback):
    for value in (user.get("userPrincipalName"), user.get("displayName"), user.get("id")):
        if value not in (None, ""):
            return clip(value)
    return clip(fallback)


def last_sign_in(activity):
    """(datetime or None, problem text). lastSuccessfulSignInDateTime first; else the later of the interactive and
    non-interactive sign-ins. (None, '') means never signed in."""
    if activity is None:
        return None, ""
    if not isinstance(activity, dict):
        return None, "signInActivity is not an object"
    raw = activity.get("lastSuccessfulSignInDateTime")
    if raw not in (None, ""):
        moment = parse_time(raw)
        if moment is None:
            return None, "lastSuccessfulSignInDateTime cannot be read"
        return moment, ""
    best = None
    for k in ("lastSignInDateTime", "lastNonInteractiveSignInDateTime"):
        raw = activity.get(k)
        if raw in (None, ""):
            continue
        moment = parse_time(raw)
        if moment is None:
            return None, k + " cannot be read"
        if best is None or moment > best:
            best = moment
    return best, ""


def evaluate(data, now):
    data = unwrap(decode(data))
    marker = marker_of(data)
    if marker is not None:
        return unevaluated(marker_problem(marker, "the getStaleAdminAccounts read"))
    if not isinstance(data, dict):
        return unevaluated("the response is not an object with roleAssignments and users")
    top = truncation_text(data, "the workflow read")
    if top:
        return unevaluated(top)
    bodies = {}
    for name in SECTIONS:
        if name not in data or data.get(name) is None:
            return unevaluated("the " + name + " list (" + ENDPOINTS[name] + ") is missing from the response")
        body = decode(data.get(name))
        problem = section_problem(name, body)
        if problem:
            return unevaluated(problem)
        bodies[name] = body

    assignments = items_of(bodies["roleAssignments"])
    users = items_of(bodies["users"])
    if assignments is None:
        return unevaluated("the role assignment list from " + ENDPOINTS["roleAssignments"] + " is not a list")
    if not users:
        return unevaluated("no users were read from " + ENDPOINTS["users"])
    if not any(isinstance(u, dict) and "signInActivity" in u for u in users):
        return unevaluated("the user read carries no signInActivity, so no sign-in date can be judged")

    users_by_id = {}
    for user in users:
        if isinstance(user, dict) and user.get("id") not in (None, ""):
            users_by_id[str(user.get("id")).lower()] = user

    admin_ids = []
    admin_seen = set()
    missing = []
    missing_seen = set()
    non_user = 0
    groups = 0
    for entry in assignments:
        if not isinstance(entry, dict):
            return unevaluated("a role assignment is not an object")
        principal = entry.get("principal") if isinstance(entry.get("principal"), dict) else {}
        pid = entry.get("principalId") or principal.get("id")
        if pid in (None, ""):
            return unevaluated("a role assignment carries no principalId")
        pid = str(pid).lower()
        kind = str(principal.get("@odata.type") or "").strip().lower()
        if kind == "#microsoft.graph.group":
            groups += 1
            continue
        if kind in NON_USER_TYPES:
            non_user += 1
            continue
        if kind == USER_TYPE or (kind == "" and pid in users_by_id):
            if pid not in users_by_id:
                if pid not in missing_seen:
                    missing_seen.add(pid)
                    missing.append(pid)
                continue
            if pid not in admin_seen:
                admin_seen.add(pid)
                admin_ids.append(pid)
            continue
        if kind == "":
            return unevaluated("role holder " + clip(pid) + " is not in the user list and its principal type is not "
                               "in the read, so it cannot be told to be a user or not")
        non_user += 1

    if missing:
        return unevaluated(str(len(missing)) + " user role holder(s) are not in the user list (a partial read), so "
                           "their sign-in cannot be read: " + name_list([clip(m) for m in missing]))
    if not admin_ids and groups:
        return unevaluated(group_text(groups) + "; no user holds an active directory role directly",
                           {"groupRoleAssignmentCount": groups})
    if not admin_ids:
        return unevaluated("no user holds an active directory role in the read (" + str(len(assignments))
                           + " assignment(s)); a tenant always has a Global Administrator, so this is a failed or "
                           "empty read")

    stale = []
    disabled = []
    never = 0
    enabled = 0
    for pid in admin_ids:
        user = users_by_id[pid]
        name = user_name(user, pid)
        account_enabled = user.get("accountEnabled")
        if isinstance(account_enabled, str) and account_enabled.strip().lower() in ("true", "false"):
            account_enabled = account_enabled.strip().lower() == "true"
        if account_enabled is False:
            disabled.append(name)
            continue
        if account_enabled is not True:
            return unevaluated("role holder " + name + " has no readable accountEnabled")
        enabled += 1
        last, problem = last_sign_in(user.get("signInActivity"))
        if problem:
            return unevaluated("role holder " + name + ": " + problem)
        if last is None:
            created = parse_time(user.get("createdDateTime"))
            if created is None:
                return unevaluated("role holder " + name + " has never signed in and its createdDateTime cannot "
                                   "be read")
            never += 1
            if older_than_window(created, now):
                stale.append(name)
            continue
        if older_than_window(last, now):
            stale.append(name)

    if enabled == 0:
        return unevaluated("no enabled user holds an active directory role (" + str(len(admin_ids))
                           + " role holder(s), all disabled)", {"groupRoleAssignmentCount": groups})

    if groups and not stale:
        return unevaluated(group_text(groups) + "; " + str(enabled) + " directly assigned role holder(s) all signed "
                           "in within " + str(STALE_DAYS) + " days, but that is not the whole admin population",
                           {"groupRoleAssignmentCount": groups, "adminCount": enabled})

    out = finish(
        stale, enabled, never, disabled,
        {"roleAssignmentCount": len(assignments), "nonUserRoleHolderCount": non_user,
         "groupRoleAssignmentCount": groups, "userCount": len(users), "pimEligibleCovered": False},
        now,
        TOOL + ": %d of %d enabled active role holders (users with an active directory role assignment) have "
        "no successful sign-in in " + str(STALE_DAYS) + "+ days",
        ["Review each role holder with no successful sign-in in " + str(STALE_DAYS) + " days: remove the role "
         "assignment or disable the account if it is no longer needed. Emergency-access (break-glass) accounts "
         "are counted too; keep them only with documented sign-in monitoring."],
        NOT_COVERED,
    )
    if groups:
        fails = out["additionalInfo"]["evaluation"]["failReasons"]
        fails[0] = fails[0] + " (" + str(groups) + " group-held role assignment(s) were not expanded; their members " \
            "are not checked)"
    return out


def group_text(groups):
    return str(groups) + " role assignments are through groups; members not checked"


def transform(input):
    try:
        return evaluate(input, utc_now())
    except Exception as e:
        return unevaluated("Transformation error: " + str(e)[:200], transformation_errors=[str(e)[:200]])
