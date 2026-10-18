"""
Transformation: staleAdminAccountCount
Vendor: Duo (Duo and Duo MSP)  |  Category: Identity / Admin Accounts

Method: workflow getStaleAdminAccounts (Integration-Service): one step, getAdmins with merge: true and no output
key, the same read superAdminMfaEnrollmentPercentage uses:
  GET /admin/v1/admins (offset paging, Admin API permission "Grant administrators - Read").
The transform receives {"response": [admin, ...]} or, once Token-Service drills the wrapper away, the bare list.
Admin objects carry admin_id, name, email, role, status, last_login (unix seconds; null = never) and created
(unix seconds).

staleAdminAccountCount = the number of ENABLED Duo console admins with no sign-in in the last STALE_DAYS (90) days:
  * every Duo admin counts, whatever its role (Duo admins are Duo console admins, not IdP admins);
  * enabled = status Active or Pending Activation; Disabled and Expired admins are not counted and are listed in
    inputSummary.disabledAdmins;
  * stale = last_login older than 90 days, or no last_login and created more than 90 days ago.
The requirement reads lessThan "0" (Token-Service: <= 0), so the check passes only at 0.
"Now" is one datetime.now(timezone.utc) read per evaluation (utc_now), reported as inputSummary.evaluatedAt.

Scope: Duo speaks only for Duo console admins. The first reason names the tool and its scope and at most 20
accounts, then "and N more"; inputSummary.affectedAccounts carries at most 50, with the full count in
affectedAccountCount (same shape as mfa/azure/legacyauthblocked.py, #891).

Unevaluated (every key None, dataCollection status "error"), never a pass, on: an error body (stat FAIL) or a
vendorErrorAsResponse marker (403 code 40301: the Admin API application lacks "Grant administrators - Read"); a
missing, empty or unrecognised admin list; a read that was not finished (paginationTruncated / truncated set, or
metadata.next_offset remaining); an unrecognised status; an unparseable last_login or created date; no enabled
admin at all; any exception.
"""

import json
from datetime import datetime, timezone

KEY = "staleAdminAccountCount"
TOOL = "Duo"
STALE_DAYS = 90
MAX_NAMED = 20
MAX_AFFECTED = 50
MAX_NAME_LEN = 100
ENABLED_STATUSES = ["active", "pending activation"]
DISABLED_STATUSES = ["disabled", "expired"]
ENDPOINT = "GET /admin/v1/admins"
REQUIRED_PERMISSION = "Grant administrators - Read"


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


# ---------------------------------------------------------------- Duo

def admins_of(data):
    """The admin list: a bare list (Token-Service drilled the {"response": [...]} wrapper away) or the list under
    response / data, at most a few wrappers deep. None when there is none."""
    value = data
    for _ in range(4):
        if isinstance(value, list):
            return value
        if not isinstance(value, dict):
            return None
        moved = False
        for k in ("response", "data", "apiResponse", "result", "Output", "_response_data"):
            if k in value and isinstance(value.get(k), (dict, list)):
                value = value[k]
                moved = True
                break
        if not moved:
            return None
    return value if isinstance(value, list) else None


def body_problem(data):
    """Why the input cannot be read as evidence, '' when it can."""
    for container in nested_dicts(data):
        marker = marker_of(container)
        if marker is not None:
            status = marker.get("status")
            body = text_of(marker.get("body"))
            if status == 403 and "40301" in body:
                return ("Duo refused " + ENDPOINT + " with HTTP 403 code 40301 (Access forbidden): the Admin API "
                        "application lacks the \"" + REQUIRED_PERMISSION + "\" permission; nothing was measured")
            return "Duo refused " + ENDPOINT + " (HTTP " + str(status)[:10] + "); nothing was measured"
        if str(container.get("stat") or "").strip().upper() == "FAIL":
            return ("Duo returned an error for " + ENDPOINT + ": " + text_of(container.get("code"))[:20] + " "
                    + text_of(container.get("message"))[:200]).strip()
        if container.get("error"):
            return "Duo returned an error for " + ENDPOINT + ": " + text_of(container.get("message")
                                                                          or container.get("error"))[:200]
        code = status_code_of(container)
        if code is not None and code >= 400:
            return "Duo answered " + ENDPOINT + " with HTTP " + str(code)
        problem = truncation_text(container, ENDPOINT)
        if problem:
            return problem
        meta = container.get("metadata")
        if isinstance(meta, dict) and link_text(meta.get("next_offset")):
            return ENDPOINT + " was not read to the end (metadata.next_offset remains)"
    return ""


def nested_dicts(data):
    """The input and the wrapper dicts around the admin list (not the admin objects themselves)."""
    out = []
    value = data
    for _ in range(4):
        if not isinstance(value, dict):
            break
        out.append(value)
        moved = False
        for k in ("response", "data", "apiResponse", "result", "Output", "_response_data"):
            if isinstance(value.get(k), dict):
                value = value[k]
                moved = True
                break
        if not moved:
            break
    return out


def is_admin_object(entry):
    return isinstance(entry, dict) and entry.get("admin_id") not in (None, "")


def admin_name(admin):
    for value in (admin.get("email"), admin.get("name"), admin.get("admin_id")):
        if value not in (None, ""):
            return clip(value)
    return "unknown"


def evaluate(data, now):
    data = decode(data)
    problem = body_problem(data)
    if problem:
        return unevaluated(problem)
    admins = admins_of(data)
    if not admins:
        return unevaluated("no Duo administrator objects were read from " + ENDPOINT + "; a Duo account always has "
                           "an Owner, so this is a failed or empty read")
    for entry in admins:
        if not is_admin_object(entry):
            return unevaluated("an entry in the " + ENDPOINT + " response is not a Duo administrator object")

    stale = []
    disabled = []
    never = 0
    enabled = 0
    seen = set()
    for admin in admins:
        admin_id = str(admin.get("admin_id"))
        if admin_id in seen:
            continue
        seen.add(admin_id)
        name = admin_name(admin)
        status = str(admin.get("status") or "").strip().lower()
        if status in DISABLED_STATUSES:
            disabled.append(name)
            continue
        if status not in ENABLED_STATUSES:
            return unevaluated("admin " + name + " has an unrecognised status '" + clip(status) + "'")
        enabled += 1
        raw_login = admin.get("last_login")
        if raw_login in (None, ""):
            created = parse_time(admin.get("created"))
            if created is None:
                return unevaluated("admin " + name + " has never signed in and its created date cannot be read")
            never += 1
            if older_than_window(created, now):
                stale.append(name)
            continue
        last = parse_time(raw_login)
        if last is None:
            return unevaluated("admin " + name + " has an unreadable last_login")
        if older_than_window(last, now):
            stale.append(name)

    if enabled == 0:
        return unevaluated("no enabled Duo administrator was found among " + str(len(seen))
                           + "; a Duo account always has an active Owner")

    return finish(
        stale, enabled, never, disabled,
        {"totalAdmins": len(seen)},
        now,
        TOOL + ": %d of %d enabled Duo console admins have no sign-in in " + str(STALE_DAYS) + "+ days",
        ["Review each Duo console admin with no sign-in in " + str(STALE_DAYS) + " days: delete the admin or "
         "set it to Disabled in the Duo Admin Panel (Administrators) if it is no longer needed."],
    )


def transform(input):
    try:
        return evaluate(input, utc_now())
    except Exception as e:
        return unevaluated("Transformation error: " + str(e)[:200], transformation_errors=[str(e)[:200]])
