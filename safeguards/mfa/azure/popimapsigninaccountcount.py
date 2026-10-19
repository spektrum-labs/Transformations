"""
Transformation: popImapSignInAccountCount
Vendor: Microsoft Entra ID (Azure AD app registration and Azure AD One-Click)  |  Category: Identity / Legacy authentication

Method: workflow getPopImapSignInEvidence (Integration-Service), one step with output.key "signIns", merge: true and
reportPagination: true, so this transform receives
  {"signIns": <Graph body>, "paginationStats": {"signIns": {"paginationTruncated": false}}}
  signIns <- getPopImapSignIns: GET /v1.0/auditLogs/signIns?$filter=createdDateTime ge {$utcNow-30d} and
             (clientAppUsed eq 'IMAP4' or clientAppUsed eq 'POP3' or clientAppUsed eq 'IMAP' or clientAppUsed eq 'POP'),
             @odata.nextLink paging. Body {"value": [{"id", "createdDateTime", "userId", "userPrincipalName",
             "userDisplayName", "clientAppUsed", "status": {"errorCode", ...}}, ...]}.
             Needs the Microsoft Graph application permission AuditLog.Read.All and a Microsoft Entra ID P1 or P2
             licence in the tenant (https://learn.microsoft.com/en-us/graph/api/signin-list,
             https://learn.microsoft.com/en-us/graph/api/resources/signin).

popImapSignInAccountCount = the number of accounts with at least one SUCCESSFUL sign-in (status.errorCode 0) whose
clientAppUsed is POP or IMAP (Graph writes "POP3" / "IMAP4"; its reference page also names "POP" / "IMAP", so all
four are accepted, case-insensitively) in the last WINDOW_DAYS (30) days. Lower is better; a requirement would read
lessThan "0" (Token-Service: <= 0).

Named evidence (tracker row 61): the first reason names the accounts, userPrincipalName first, then the display
name, then the user id, each with the protocols it used, capped at MAX_NAMED (25) plus "and N more".
inputSummary.affectedAccounts carries at most MAX_AFFECTED (50), with the full number in affectedAccountCount.
Accounts whose POP or IMAP sign-ins all FAILED (blocked by policy or wrong credentials) are not counted; they are
named in an additional finding, because the protocol is still being tried against them.

The window is the definition's {$utcNow-30d} filter; the transform does not re-filter by date.

Completeness: 0 is reported only from a read Integration-Service marks complete (paginationStats.signIns.
paginationTruncated is false) with no next link left in the body. A read that stopped early with accounts found
still fails, as "at least N", because each named account is a real successful sign-in; a read that stopped early
with none found is Not evaluated.

Not evaluated (popImapSignInAccountCount None, dataCollection status "error"), never a pass or a fail, on: an error
body; a vendorErrorAsResponse marker (403 Authorization_RequestDenied: the app lacks AuditLog.Read.All; 403 naming a
premium licence: the tenant has no Entra ID P1 or P2); any other refusal; a missing or unrecognised sign-in list; a
sign-in that is not an object or carries no readable status.errorCode; a read that cannot be shown complete with
no account found; any exception.

Not covered: the v1.0 sign-in log lists interactive sign-ins, so an OAuth POP or IMAP client that only refreshes
its token (non-interactive sign-ins) is not seen. Whether POP or IMAP is switched ON for a mailbox (Exchange Online
CAS mailbox PopEnabled / ImapEnabled) is not read: Microsoft documents no app-only REST read for it (the Exchange
Online Admin API has no CASMailbox endpoint). Google Workspace is not covered by this file.
"""

import json
from datetime import datetime, timezone

KEY = "popImapSignInAccountCount"
TOOL = "Microsoft Entra ID"
SECTION = "signIns"
ENDPOINT = "GET /v1.0/auditLogs/signIns (POP and IMAP sign-ins)"
WINDOW_DAYS = 30
MAX_NAMED = 25
MAX_AFFECTED = 50
MAX_NAME_LEN = 100
PROTOCOLS = {"pop3": "POP3", "pop": "POP3", "imap4": "IMAP4", "imap": "IMAP4"}
NOT_COVERED = ("Not covered: only interactive sign-ins are read, so an OAuth POP or IMAP client that only refreshes "
               "its token is not seen; whether POP or IMAP is switched on for each mailbox (Exchange Online mailbox "
               "settings) is not read.")


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


def unevaluated(reason, summary=None, transformation_errors=None):
    """Nothing was measured: the key is None, never 0."""
    text = str(reason)[:500]
    return create_response({KEY: None}, fail_reasons=["Not evaluated: " + text], api_errors=[text],
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
    text = str(value or "").strip()
    return "" if text in ("None", "null") else text


def truncation_text(value, label):
    """Why a read is not complete, '' when nothing in the body says so."""
    if not isinstance(value, dict):
        return ""
    blocks = [value]
    for k in ("response_metadata", "metadata", "pagination"):
        if isinstance(value.get(k), dict):
            blocks.append(value[k])
    for block in blocks:
        for k in ("paginationTruncated", "truncated"):
            if k in block and flag_set(block.get(k)):
                return label + " was not read to the end (" + k + " is set)"
    if link_text(value.get("@odata.nextLink")):
        return label + " was not read to the end (@odata.nextLink remains)"
    return ""


def marker_problem(marker):
    status = marker.get("status")
    body = text_of(marker.get("body"))
    low = body.lower()
    if status == 403 and ("premium" in low or "licen" in low):
        return ("needs Entra ID P1: Microsoft Graph refused " + ENDPOINT + " with HTTP 403 because sign-in logs "
                "need a Microsoft Entra ID P1 or P2 licence, which this tenant does not have; nothing was measured")
    if status == 403 and ("authorization_requestdenied" in low or "accessdenied" in low):
        return ("Microsoft Graph refused " + ENDPOINT + " with HTTP 403: the app lacks the AuditLog.Read.All "
                "application permission; nothing was measured")
    if status == 400:
        return "Microsoft Graph rejected " + ENDPOINT + " (HTTP 400): " + body[:200]
    if status == 429:
        return "Microsoft Graph throttled " + ENDPOINT + " (HTTP 429); nothing was measured"
    return "Microsoft Graph refused " + ENDPOINT + " (HTTP " + str(status)[:10] + "); nothing was measured"


def body_problem(body):
    """Why the sign-in body cannot be read as evidence, '' when it can."""
    marker = marker_of(body)
    if marker is not None:
        return marker_problem(marker)
    if not isinstance(body, dict):
        return "the sign-in list from " + ENDPOINT + " is not an object"
    error = body.get("error")
    if error:
        if isinstance(error, dict):
            return ("Microsoft Graph returned an error for " + ENDPOINT + ": "
                    + text_of(error.get("code"))[:80] + " " + text_of(error.get("message"))[:200]).strip()
        return "Microsoft Graph returned an error for " + ENDPOINT + ": " + text_of(body.get("message") or error)[:200]
    code = status_code_of(body)
    if code is not None and code >= 400:
        return "Microsoft Graph answered " + ENDPOINT + " with HTTP " + str(code)
    if not isinstance(body.get("value"), list):
        return "the sign-in list from " + ENDPOINT + " carries no value list"
    return ""


def unwrap(value):
    for _ in range(4):
        if not isinstance(value, dict) or SECTION in value or "value" in value or "vendorErrorAsResponse" in value:
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


def clip(value):
    return str(value).strip()[:MAX_NAME_LEN]


def name_list(items):
    """At most MAX_NAMED names, then 'and N more'."""
    shown = ", ".join(items[:MAX_NAMED])
    if len(items) > MAX_NAMED:
        shown = shown + " and " + str(len(items) - MAX_NAMED) + " more"
    return shown


def error_code_of(entry):
    """status.errorCode as an int, or None when it cannot be read."""
    status = entry.get("status")
    if not isinstance(status, dict):
        return None
    code = status.get("errorCode")
    if isinstance(code, bool):
        return None
    if isinstance(code, int):
        return code
    if isinstance(code, str) and code.strip().isdigit():
        return int(code.strip())
    return None


def account_of(entry):
    """(grouping key, shown name) for one sign-in: userPrincipalName, then display name, then user id."""
    upn = str(entry.get("userPrincipalName") or "").strip()
    display = str(entry.get("userDisplayName") or "").strip()
    uid = str(entry.get("userId") or "").strip()
    shown = upn or display or uid
    if not shown:
        shown = "unnamed account (sign-in " + clip(entry.get("id") or "with no id") + ")"
    key = (uid or upn or display or shown).lower()
    return key, clip(shown)


def labelled(accounts):
    """'name (IMAP4, POP3)' for each account, sorted by name."""
    out = []
    for key in accounts:
        entry = accounts[key]
        out.append(entry["name"] + " (" + ", ".join(sorted(entry["protocols"])) + ")")
    return sorted(out, key=lambda s: s.lower())


def completeness(data, body):
    """'' when the read is shown complete, else why not."""
    stats = data.get("paginationStats") if isinstance(data, dict) else None
    own = stats.get(SECTION) if isinstance(stats, dict) else None
    flag = own.get("paginationTruncated") if isinstance(own, dict) else None
    reason = truncation_text(body, "the sign-in log") or truncation_text(data, "the sign-in log")
    if reason:
        return reason
    if flag is False:
        return ""
    if flag is None:
        return "the sign-in log read carries no completeness marker (paginationStats.signIns), so it cannot be shown complete"
    return "the sign-in log was not read to the end (paginationTruncated is set)"


def evaluate(data):
    data = unwrap(decode(data))
    marker = marker_of(data)
    if marker is not None:
        return unevaluated(marker_problem(marker))
    if not isinstance(data, dict):
        return unevaluated("the response is not an object with a sign-in list")
    if SECTION in data:
        body = unwrap(decode(data.get(SECTION)))
    elif "value" in data:
        body = data
    else:
        return unevaluated("the sign-in list (" + ENDPOINT + ") is missing from the response")
    problem = body_problem(body)
    if problem:
        return unevaluated(problem)

    used = {}
    tried = {}
    read = 0
    other = 0
    for entry in body["value"]:
        if not isinstance(entry, dict):
            return unevaluated("a sign-in in the list is not an object")
        protocol = PROTOCOLS.get(str(entry.get("clientAppUsed") or "").strip().lower())
        if protocol is None:
            other += 1
            continue
        read += 1
        code = error_code_of(entry)
        if code is None:
            return unevaluated("a " + protocol + " sign-in carries no readable status.errorCode, so success cannot "
                               "be told from failure")
        key, name = account_of(entry)
        target = used if code == 0 else tried
        if key not in target:
            target[key] = {"name": name, "protocols": set()}
        target[key]["protocols"].add(protocol)

    for key in used:
        if key in tried:
            tried.pop(key)

    incomplete = completeness(data, body)
    affected = labelled(used)
    attempted = labelled(tried)
    summary = {
        "affectedAccounts": affected[:MAX_AFFECTED],
        "affectedAccountCount": len(affected),
        "failedAttemptAccounts": attempted[:MAX_AFFECTED],
        "failedAttemptAccountCount": len(attempted),
        "popImapSignInsRead": read,
        "otherSignInsIgnored": other,
        "windowDays": WINDOW_DAYS,
        "readComplete": incomplete == "",
    }
    findings = []
    if attempted:
        findings.append(TOOL + ": " + str(len(attempted)) + " account(s) had POP or IMAP sign-in attempts in the last "
                        + str(WINDOW_DAYS) + " days that all failed (blocked or wrong credentials), so the protocol "
                        "is still being tried against them: " + name_list(attempted))

    if not affected and incomplete:
        return unevaluated(incomplete + "; no successful POP or IMAP sign-in was found in the part that was read",
                           summary)

    result = {KEY: len(affected)}
    if affected:
        lead = (TOOL + " sign-in log: " + ("at least " if incomplete else "") + str(len(affected))
                + " account(s) signed in successfully with POP or IMAP in the last " + str(WINDOW_DAYS) + " days: "
                + name_list(affected))
        reasons = [lead]
        if incomplete:
            reasons.append(incomplete + ", so more accounts may have used POP or IMAP")
        reasons.append(NOT_COVERED)
        return create_response(
            result, fail_reasons=reasons, input_summary=summary, additional_findings=findings,
            recommendations=["Move each account named above to a modern-authentication client (Outlook, or an "
                             "OAuth-capable mail app), then switch POP and IMAP off for those mailboxes "
                             "(Set-CASMailbox -PopEnabled $false -ImapEnabled $false) and block legacy "
                             "authentication with Conditional Access."])
    return create_response(
        result,
        pass_reasons=[TOOL + " sign-in log: no account signed in successfully with POP or IMAP in the last "
                      + str(WINDOW_DAYS) + " days (" + str(read) + " POP or IMAP sign-in(s) read, all failed)"
                      if read else
                      TOOL + " sign-in log: no account signed in with POP or IMAP in the last " + str(WINDOW_DAYS)
                      + " days", NOT_COVERED],
        input_summary=summary, additional_findings=findings)


def transform(input):
    try:
        return evaluate(input)
    except Exception as e:
        return unevaluated("Transformation error: " + str(e)[:200], transformation_errors=[str(e)[:200]])
