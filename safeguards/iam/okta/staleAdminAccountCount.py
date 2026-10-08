"""
Transformation: staleAdminAccountCount
Vendor: Okta  |  Category: Identity / Admin Accounts

Method: workflow getStaleAdminAccounts (Integration-Service), two steps, each with output.key and merge: true,
so this transform receives {"adminAssignees": <body>, "users": <body>}:
  adminAssignees <- listAdminAssignees: GET /api/v1/iam/assignees/users?limit=200, body-link paging
                    (_links.next.href). Body {"value": [{"id", "orn", "_links"}, ...], "_links": {...}}: the users
                    Okta lists as holding an admin role assignment.
  users          <- listUsersLastLogin: GET /api/v1/users?limit=200, Link-header paging. A bare array of Okta user
                    objects (id, status, created, lastLogin, profile.login / profile.email). Okta leaves
                    DEPROVISIONED users out of this list by default.

staleAdminAccountCount = the number of ENABLED Okta admins with no sign-in in the last STALE_DAYS (90) days:
  * an admin is a user id in the assignees list, joined to the user list on id;
  * enabled = any status but SUSPENDED / DEPROVISIONED (STAGED and PROVISIONED admins count: they can be
    activated and hold the role);
  * stale = lastLogin older than 90 days, or no lastLogin at all and created more than 90 days ago;
  * suspended and deprovisioned admins are not counted; they are listed in inputSummary.disabledAdmins.
The requirement reads lessThan "0" (Token-Service: <= 0), so the check passes only at 0.
"Now" is one datetime.now(timezone.utc) read per evaluation (utc_now), reported as inputSummary.evaluatedAt.

Scope: Okta speaks only for Okta admins. The first reason names the tool and its scope and at most 20 accounts,
then "and N more"; inputSummary.affectedAccounts carries at most 50, with the full count in affectedAccountCount
(same shape as mfa/azure/legacyauthblocked.py, #891).

Unevaluated (every key None, dataCollection status "error"), never a pass, on: an error body or a
vendorErrorAsResponse marker (a 403 means the API token's administrator cannot read role assignments); a missing,
empty or unrecognised assignee or user list; a read that was not finished (paginationTruncated / truncated set, or
an unread next link); an admin whose id is not in the user list (a partial read, or a deprovisioned admin); an
unrecognised status; an unparseable lastLogin or created date; no enabled admin at all; any exception.

This file is byte-identical to safeguards/86ded564-522a-4c9b-9106-365e4cbdec7d/staleadminaccountcount.py
(test_okta_stale_admin_account_count.py enforces it).
"""

import json
from datetime import datetime, timezone

KEY = "staleAdminAccountCount"
TOOL = "Okta"
STALE_DAYS = 90
MAX_NAMED = 20
MAX_AFFECTED = 50
MAX_NAME_LEN = 100
ENABLED_STATUSES = ["ACTIVE", "PASSWORD_EXPIRED", "LOCKED_OUT", "RECOVERY", "STAGED", "PROVISIONED"]
DISABLED_STATUSES = ["SUSPENDED", "DEPROVISIONED"]
SECTIONS = ["adminAssignees", "users"]
ENDPOINTS = {
    "adminAssignees": "GET /api/v1/iam/assignees/users",
    "users": "GET /api/v1/users",
}


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


# ---------------------------------------------------------------- Okta

def unwrap(value):
    for _ in range(4):
        if not isinstance(value, dict) or "adminAssignees" in value or "users" in value:
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


def section_problem(name, body):
    """Why a section cannot be read as evidence, '' when it can."""
    endpoint = ENDPOINTS[name]
    marker = marker_of(body)
    if marker is not None:
        status = marker.get("status")
        if status == 403:
            return ("Okta refused " + endpoint + " with HTTP 403: the API token's administrator cannot read "
                    "admin role assignments (okta.roles.read; a super or org administrator token can)")
        return "Okta refused " + endpoint + " (HTTP " + str(status)[:10] + ")"
    if isinstance(body, dict):
        for k in ("errorCode", "errorSummary", "error", "errors", "errorMessage"):
            if body.get(k):
                return "Okta returned an error for " + endpoint + ": " + text_of(body.get(k))[:200]
        code = status_code_of(body)
        if code is not None and code >= 400:
            return "Okta answered " + endpoint + " with HTTP " + str(code)
        return truncation_text(body, endpoint)
    return ""


def items_of(body):
    if isinstance(body, list):
        return body
    if isinstance(body, dict) and isinstance(body.get("value"), list):
        return body["value"]
    return None


def user_name(user, fallback):
    profile = user.get("profile") if isinstance(user.get("profile"), dict) else {}
    for value in (profile.get("login"), profile.get("email"), user.get("id")):
        if value not in (None, ""):
            return clip(value)
    return clip(fallback)


def evaluate(data, now):
    data = unwrap(decode(data))
    marker = marker_of(data)
    if marker is not None:
        return unevaluated("Okta refused the call (HTTP " + str(marker.get("status"))[:10] + "); nothing was measured")
    if not isinstance(data, dict):
        return unevaluated("the response is not an object with adminAssignees and users")
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

    assignees = items_of(bodies["adminAssignees"])
    users = items_of(bodies["users"])
    if not assignees:
        return unevaluated("no admin role holders were read from " + ENDPOINTS["adminAssignees"]
                           + "; an Okta org always has a super administrator, so this is a failed or empty read")
    if not users:
        return unevaluated("no users were read from " + ENDPOINTS["users"])

    users_by_id = {}
    for user in users:
        if isinstance(user, dict) and user.get("id") not in (None, ""):
            users_by_id[str(user.get("id"))] = user

    admin_ids = []
    admin_seen = set()
    for entry in assignees:
        admin_id = entry.get("id") if isinstance(entry, dict) else None
        if admin_id in (None, ""):
            return unevaluated("an admin role holder in " + ENDPOINTS["adminAssignees"] + " carries no user id")
        if str(admin_id) not in admin_seen:
            admin_seen.add(str(admin_id))
            admin_ids.append(str(admin_id))

    missing = [a for a in admin_ids if a not in users_by_id]
    if missing:
        return unevaluated(str(len(missing)) + " of " + str(len(admin_ids)) + " admin role holder(s) are not in the "
                           "user list (a partial read, or a deprovisioned admin), so their sign-in cannot be read: "
                           + name_list([clip(m) for m in missing]))

    stale = []
    disabled = []
    never = 0
    enabled = 0
    for admin_id in admin_ids:
        user = users_by_id[admin_id]
        name = user_name(user, admin_id)
        status = str(user.get("status") or "").strip().upper()
        if status in DISABLED_STATUSES:
            disabled.append(name)
            continue
        if status not in ENABLED_STATUSES:
            return unevaluated("admin " + name + " has an unrecognised status '" + clip(status) + "'")
        enabled += 1
        raw_login = user.get("lastLogin")
        if raw_login in (None, ""):
            created = parse_time(user.get("created"))
            if created is None:
                return unevaluated("admin " + name + " has never signed in and its created date cannot be read")
            never += 1
            if older_than_window(created, now):
                stale.append(name)
            continue
        last = parse_time(raw_login)
        if last is None:
            return unevaluated("admin " + name + " has an unreadable lastLogin date")
        if older_than_window(last, now):
            stale.append(name)

    if enabled == 0:
        return unevaluated("no enabled admin was found among " + str(len(admin_ids)) + " admin role holder(s); "
                           "an Okta org always has an active super administrator")

    return finish(
        stale, enabled, never, disabled,
        {"adminRoleHolderCount": len(admin_ids), "userCount": len(users)},
        now,
        TOOL + ": %d of %d enabled Okta admins (users holding an admin role) have no sign-in in "
        + str(STALE_DAYS) + "+ days",
        ["Review each Okta admin with no sign-in in " + str(STALE_DAYS) + " days: remove the admin role or "
         "suspend the account if it is no longer needed. Emergency (break-glass) admins are counted too; keep "
         "them only with documented monitoring."],
    )


def transform(input):
    try:
        return evaluate(input, utc_now())
    except Exception as e:
        return unevaluated("Transformation error: " + str(e)[:200], transformation_errors=[str(e)[:200]])
