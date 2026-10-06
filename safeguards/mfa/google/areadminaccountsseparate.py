"""
Transformation: areAdminAccountsSeparate
Vendor: Google Workspace  |  Integrations: Google - MFA (5cdba755), Google - Email Security (dbc425fa)
Category: Identity / Admin Accounts

Claim (IAM-004 Admin Account Segmentation): every account holding a privileged role in the identity
provider is a dedicated admin account, separate from the person's everyday account: no mailbox and no
productivity licence. Pass = isEquals true.

EVIDENCE. Directory API users.list (GET admin/directory/v1/users?customer=my_customer, the definition's
listUserAccounts method, paged with maxResults/pageToken). Scope admin.directory.user.readonly, which
both Google definitions already request. Fields read per user (Google "User" resource):
  isAdmin           the user holds the Super Admin role
  isDelegatedAdmin  the user holds a delegated (non-super) admin role
  isMailboxSetup    "Indicates if the user's Google mailbox is created. This property is only applicable
                    if the user has been assigned a Gmail license."
  suspended, archived, primaryEmail, id

RULE. Administrators are users with isAdmin or isDelegatedAdmin true. Each ACTIVE administrator (not
suspended, not archived) must have no Gmail mailbox:
  * isMailboxSetup true   -> the admin account has a Gmail mailbox, so it is a licensed everyday Workspace
                             account: a measured fail.
  * isMailboxSetup false  -> no mailbox: a dedicated admin account (the usual pattern is a Super Admin
                             with a Cloud Identity licence and no Workspace licence).
  * isMailboxSetup absent -> that admin cannot be classified: not evaluated.
primaryEmail is the Google sign-in name and exists on every account, mailbox or not, so it is never
evidence on its own (the Microsoft rule treats a bare `mail` attribute the same way).
Suspended and archived admins cannot sign in; they are counted and not judged.

WHAT THIS DOES NOT SEE. A Google Workspace licence whose Gmail service is switched off for the admin's
organisational unit leaves isMailboxSetup false while the account still holds Docs/Drive. Reading
licence assignments needs the Enterprise License Manager API (scope apps.licensing), which neither
Google definition requests; adding it changes every customer's domain-wide delegation, so it is not
added here. The pass reason therefore says "no Gmail mailbox", which is what was read.

FAIL CLOSED. Null, {}, an error envelope or missing scope, no users list, a list still carrying
nextPageToken or flagged paginationTruncated, no active administrator (every tenant has a Super Admin),
or an administrator without isMailboxSetup returns areAdminAccountsSeparate = None with a dataCollection
error ("not evaluated"). One active administrator shown to have a mailbox is a measured fail, whatever
else is missing. Google bodies can carry booleans as the strings "True"/"False"; both are read.
"""

import json
from datetime import datetime

#: The criteria this file answers. A None among them means "not measured", never "failed".
NONE_MEANS_NOT_EVALUATED = ('areAdminAccountsSeparate',)

CRITERIA_KEY = "areAdminAccountsSeparate"
REQUIRED_SCOPE = "https://www.googleapis.com/auth/admin.directory.user.readonly"
WRAPPER_KEYS = ["api_response", "apiResponse", "response", "result", "Output", "rawResponse", "data"]
SCOPE_HINTS = ["scope_not_granted", "access_denied", "unauthorized_client",
               "insufficient authentication scopes", "access_token_scope_insufficient",
               "request had insufficient authentication"]
MAX_NAMED = 20
MAX_AFFECTED = 50
META = {"transformationId": CRITERIA_KEY, "vendor": "Google Workspace", "category": "Identity"}


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    return input_data, {"status": "unknown", "errors": [],
                        "warnings": ["Legacy input format - no schema validation performed"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None,
                    transformation_errors=None, api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    response_metadata = {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "2.0"}
    response_metadata.update(META)
    if metadata:
        response_metadata.update(metadata)
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success",
                               "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"),
                           "errors": validation.get("errors", []),
                           "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success",
                               "errors": transformation_errors or [],
                               "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                           "recommendations": recommendations or [],
                           "additionalFindings": additional_findings or []},
            "metadata": response_metadata,
        },
    }


def is_true(value):
    """Google bodies reach us with booleans as the strings "True"/"False"; bool("False") is True."""
    return value is True or str(value).strip().lower() == "true"


def is_false(value):
    return value is False or str(value).strip().lower() == "false"


def error_reason(body):
    """A short reason when the body is an error envelope, else None."""
    if not isinstance(body, dict):
        return None
    err = body.get("error")
    text = ""
    if isinstance(err, dict):
        text = str(err.get("code") or "") + " " + str(err.get("status") or "") + " " + str(err.get("message") or "")
    elif isinstance(err, str) and err:
        text = err + " " + str(body.get("error_description") or "")
    elif err is True:
        text = str(body.get("statusCode") or body.get("status_code") or "") + " error"
    else:
        for key in ["statusCode", "status_code"]:
            code = body.get(key)
            if isinstance(code, str) and code.strip().isdigit():
                code = int(code.strip())
            if isinstance(code, int) and not isinstance(code, bool) and code >= 400:
                text = str(code) + " " + str(body.get("message") or body.get("error") or "")
    if not text.strip():
        return None
    lower = text.lower()
    for hint in SCOPE_HINTS:
        if hint in lower:
            return "Google refused the Directory read for lack of scope (" + REQUIRED_SCOPE + ")"
    if "401" in text or "403" in text:
        return "Google refused the Directory users read (" + text.strip()[:80] + ")"
    return "Google returned an error for the Directory users read (" + text.strip()[:80] + ")"


def users_body(data):
    """The users.list body (a dict with a `users` list), (None, reason) when it is not one."""
    body = data
    for depth in range(5):
        reason = error_reason(body)
        if reason:
            return None, reason
        if isinstance(body, list):
            body = {"users": body}
        if not isinstance(body, dict):
            return None, "No Directory users list in the response"
        users = body.get("users")
        if isinstance(users, list):
            return body, None
        if isinstance(users, dict):
            body = users
            continue
        found = None
        for key in WRAPPER_KEYS:
            if isinstance(body.get(key), (dict, list)):
                found = body.get(key)
                break
        if found is None:
            return None, "No Directory users list in the response"
        body = found
    return None, "No Directory users list in the response"


def name_of(user):
    return str(user.get("primaryEmail") or user.get("id") or "unknown").strip()[:100]


def name_list(items):
    shown = ", ".join(items[:MAX_NAMED])
    if len(items) > MAX_NAMED:
        shown = shown + " and " + str(len(items) - MAX_NAMED) + " more"
    return shown


def not_evaluated(validation, reason, summary=None, findings=None, extra=None):
    result = {CRITERIA_KEY: None, "adminCount": None, "adminsWithMailbox": None}
    if extra:
        result.update(extra)
        result[CRITERIA_KEY] = None
    return create_response(
        result=result, validation=validation, api_errors=[reason],
        fail_reasons=["Admin account separation was not evaluated: " + reason],
        recommendations=["Confirm the Google integration can list every Directory user (scope "
                         + REQUIRED_SCOPE + ") and that the read is not cut off"],
        input_summary=summary or {}, additional_findings=findings or [])


def transform(input):
    try:
        if isinstance(input, str):
            input = json.loads(input) if input.strip() else None
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return not_evaluated(validation, "input validation failed: " + "; ".join(validation.get("errors", [])))

        body, reason = users_body(data)
        if body is None:
            return not_evaluated(validation, reason)

        users = [u for u in body["users"] if isinstance(u, dict)]
        truncated = bool(body.get("nextPageToken")) or is_true(body.get("paginationTruncated")) \
            or (isinstance(data, dict) and is_true(data.get("paginationTruncated")))

        admins = [u for u in users if is_true(u.get("isAdmin")) or is_true(u.get("isDelegatedAdmin"))]
        inactive = [u for u in admins if is_true(u.get("suspended")) or is_true(u.get("archived"))]
        active = [u for u in admins if not (is_true(u.get("suspended")) or is_true(u.get("archived")))]

        with_mailbox = []
        unclassified = []
        dedicated = 0
        for admin in active:
            flag = admin.get("isMailboxSetup")
            if is_true(flag):
                with_mailbox.append(name_of(admin))
            elif is_false(flag):
                dedicated = dedicated + 1
            else:
                unclassified.append(name_of(admin))

        summary = {"userCount": len(users), "adminCount": len(admins), "activeAdminCount": len(active),
                   "superAdminCount": len([u for u in active if is_true(u.get("isAdmin"))]),
                   "delegatedAdminCount": len([u for u in active if not is_true(u.get("isAdmin"))]),
                   "inactiveAdminCount": len(inactive), "dedicatedAdminCount": dedicated,
                   "unclassifiedAdminCount": len(unclassified), "truncated": truncated,
                   "affectedAccounts": with_mailbox[:MAX_AFFECTED], "affectedAccountCount": len(with_mailbox)}
        findings = []
        if inactive:
            findings.append(str(len(inactive)) + " administrator account(s) are suspended or archived (not judged)")
        counts = {"adminCount": len(active), "adminsWithMailbox": len(with_mailbox)}

        if with_mailbox:
            reason = (str(len(with_mailbox)) + " of " + str(len(active)) + " active Google administrator account(s) "
                      "have a Gmail mailbox, so they are everyday Workspace accounts rather than dedicated admin "
                      "accounts: " + name_list(with_mailbox))
            if truncated or unclassified:
                reason = reason + "; the read was also incomplete, so more may be affected"
            result = {CRITERIA_KEY: False}
            result.update(counts)
            return create_response(
                result=result, validation=validation, fail_reasons=[reason],
                recommendations=["Give each administrator a separate admin-only account with no Gmail mailbox and "
                                 "no Workspace licence (for example a Cloud Identity licence), and remove admin "
                                 "roles from everyday accounts"],
                input_summary=summary, additional_findings=findings)

        if truncated:
            return not_evaluated(validation, "the Directory users list was truncated (nextPageToken present); not "
                                             "every administrator was read", summary, findings, counts)
        if not active:
            return not_evaluated(validation, "no active administrator was returned; every Google tenant has a Super "
                                             "Admin, so the list cannot be complete", summary, findings, counts)
        if unclassified:
            return not_evaluated(validation, str(len(unclassified)) + " administrator account(s) carry no "
                                 "isMailboxSetup field, so whether they have a mailbox is unknown: "
                                 + name_list(unclassified), summary, findings, counts)

        result = {CRITERIA_KEY: True}
        result.update(counts)
        return create_response(
            result=result, validation=validation,
            pass_reasons=["All " + str(len(active)) + " active Google administrator account(s) have no Gmail "
                          "mailbox: they are dedicated admin accounts"],
            input_summary=summary, additional_findings=findings)
    except Exception as e:
        message = "Transformation error: " + str(e)[:200]
        return create_response(
            result={CRITERIA_KEY: None, "adminCount": None, "adminsWithMailbox": None},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[message], api_errors=[message], fail_reasons=[message])
