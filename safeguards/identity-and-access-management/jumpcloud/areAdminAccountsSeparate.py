"""
Transformation: areAdminAccountsSeparate
Vendor: JumpCloud  |  Integration: JumpCloud-Identity and Access Management (7b2c0d10)
Category: Identity and Access Management

Claim (IAM-004 Admin Account Segmentation): every account holding a privileged role in the identity
provider is a dedicated admin account, separate from the person's everyday account. Pass = isEquals true.

EVIDENCE. Two reads the definition already has, merged by one Integration-Service workflow:
  administrators  GET https://console.jumpcloud.com/api/users        (method listAdministrators)
                  JumpCloud Admin Portal administrators: {"results": [{_id, email, roleName, roleNames,
                  suspended, ...}], "totalCount": N}. Paged with limit/skip.
  systemUsers     GET https://console.jumpcloud.com/api/systemusers  (method listSystemUsers)
                  JumpCloud directory (everyday) users: {"results": [{_id, email, alternateEmail,
                  username, state, suspended, activated, ...}], "totalCount": N}. Paged with limit/skip.
Both authenticate with the definition's x-api-key, which acts with the rights of the administrator who
owns it; JumpCloud has no OAuth scope, so nothing new is asked of the customer.

WHY THESE TWO LISTS. In JumpCloud an administrator is a separate object from a directory user: it
signs in to the Admin Portal, while the directory user is the everyday identity that signs in to
devices, the User Portal, SSO apps and (through directory sync) the mailbox. The two are joined only by
the email address. An administrator whose email IS an active directory user's email is that person's
everyday identity with admin rights attached: its password resets, MFA prompts and admin notices go to
the everyday mailbox, and a phish of that mailbox reaches the Admin Portal. A dedicated admin account
uses an admin-only address that no everyday directory user carries (for example admin-jdoe@).

RULE. Each ACTIVE administrator (suspended false) is compared, by email, with each directory user's
email AND alternateEmail. Addresses are trimmed, lower-cased and plus-folded (local+tag@domain is read
as local@domain, so jdoe+admin@ is the same mailbox as jdoe@):
  * matches an ACTIVE directory user (not suspended, state not SUSPENDED; STAGED users count, because
    they become active when scheduled)  -> not separate: a measured fail.
  * matches only a SUSPENDED directory user  -> separate (the everyday identity cannot sign in);
    reported as a finding.
  * matches no directory user  -> a dedicated admin account.
  * has no email  -> cannot be classified: not evaluated.
Every admin role is judged (Administrator With Billing, Administrator, Manager, Help Desk, Read Only,
custom), as every Admin Portal account can see or change the directory. Suspended administrators cannot
sign in; they are counted and not judged. Provider (MSP) administrators are not in /api/users and are
not judged. Administrator emails are never copied into the output: accounts are named by record id.

A PASS NEEDS EVIDENCE THAT COULD HAVE FAILED. If the org's everyday identities are not JumpCloud
directory users (JumpCloud used only for devices or admin access, users mastered elsewhere), no admin
email can match and every admin would read "dedicated" while nothing was learned. So a pass must cover
EVERY active administrator: when the directory has no ACTIVE user, or ANY active administrator's email
domain is one no active directory user's primary email is on, the result is None (not evaluated), the
same as an administrator with no email, and the reason names those administrators by record id. Domains
come from the primary `email` only: alternateEmail is often a personal address (gmail.com, outlook.com)
and would let a personal-address admin look "on a directory domain". alternateEmail is still matched as
an address (an admin whose email is a user's alternateEmail is that user's everyday identity).

FAIL CLOSED. Null, {}, an error envelope (401/403/5xx, {"error": ...}), either list missing, a list
without totalCount or shorter than its totalCount (a partial read), a paginationTruncated flag, no
active administrator, an administrator with no email, no active directory user, or any active
administrator on an email domain no active directory user's primary email is on returns areAdminAccountsSeparate = None with a dataCollection
error ("not evaluated"). The workflow's paginationTruncated markers (top level or
paginationStats.<key>) are read too. One active administrator shown to share an active everyday
identity is a measured fail, whatever else is missing.
"""

import json
from datetime import datetime

#: The criteria this file answers. A None among them means "not measured", never "failed".
NONE_MEANS_NOT_EVALUATED = ('areAdminAccountsSeparate',)

KEY = "areAdminAccountsSeparate"
META = {"transformationId": KEY, "vendor": "JumpCloud", "category": "identity-and-access-management"}
WRAPPER_KEYS = ["api_response", "apiResponse", "response", "result", "Output", "rawResponse"]
ADMIN_KEYS = ["administrators", "listAdministrators", "admins"]
USER_KEYS = ["systemUsers", "listSystemUsers", "systemusers"]
MAX_NAMED = 20
MAX_AFFECTED = 50


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    return unwrap(input_data), {"status": "unknown", "errors": [],
                                "warnings": ["Legacy input format - no schema validation performed"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None, recommendations=None,
                    input_summary=None, api_errors=None, transformation_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    metadata = {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "2.0"}
    metadata.update(META)
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []),
                           "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success",
                               "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                           "recommendations": recommendations or [],
                           "additionalFindings": additional_findings or []},
            "metadata": metadata,
        },
    }


def unwrap(data):
    for depth in range(4):
        if not isinstance(data, dict):
            return data
        found = None
        for key in WRAPPER_KEYS:
            if key in data and isinstance(data.get(key), (dict, list)):
                found = key
                break
        if found is None:
            return data
        data = data[found]
    return data


def as_count(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def truthy(value):
    if isinstance(value, bool):
        return value
    return isinstance(value, str) and value.strip().lower() == "true"


def error_reason(body):
    if not isinstance(body, dict):
        return None
    err = body.get("error")
    if isinstance(err, dict):
        return "JumpCloud returned an error (" + str(err.get("code") or err.get("statusCode") or "")[:12] + " " \
            + str(err.get("message") or "")[:80] + ")"
    if isinstance(err, str) and err:
        return "JumpCloud returned an error (" + str(body.get("statusCode") or body.get("status_code") or "")[:12] \
            + " " + err[:80] + ")"
    if err is True:
        return "JumpCloud returned an error (HTTP " + str(body.get("statusCode") or "")[:12] + ")"
    marked = body.get("vendorErrorAsResponse")
    if isinstance(marked, dict):
        return "JumpCloud answered HTTP " + str(marked.get("status"))[:8]
    for key in ["statusCode", "status_code"]:
        code = as_count(body.get(key))
        if code is not None and code >= 400:
            return "JumpCloud answered HTTP " + str(code)
    message = body.get("message")
    if isinstance(message, str) and "unauthorized" in message.lower():
        return "JumpCloud refused the request (" + message[:80] + ")"
    return None


def pick(data, keys):
    for key in keys:
        if key in data:
            return key, unwrap(data.get(key))
    return None, None


def full_list(block, label):
    """(records, None) for a complete JumpCloud list, or (None, reason)."""
    reason = error_reason(block)
    if reason:
        return None, "the " + label + " read failed: " + reason
    if not isinstance(block, dict) or not isinstance(block.get("results"), list):
        return None, "no " + label + " list in the response"
    records = block.get("results")
    if not all(isinstance(r, dict) for r in records):
        return None, "the " + label + " list is not a list of JumpCloud records"
    total = as_count(block.get("totalCount"))
    if total is None:
        return None, "the " + label + " list carries no totalCount, so completeness cannot be confirmed"
    if len(records) < total:
        return None, ("only " + str(len(records)) + " of " + str(total) + " " + label
                      + " were read; a partial list is not evaluated")
    if truthy(block.get("paginationTruncated")):
        return None, "the " + label + " list was cut off before its last page"
    return records, None


def fold(value):
    """An address trimmed, lower-cased and plus-folded (local+tag@domain -> local@domain), or ""."""
    if not isinstance(value, str):
        return ""
    text = value.strip().lower()
    if text.count("@") != 1:
        return text
    local, domain = text.split("@")
    if "+" in local:
        local = local.split("+")[0]
    if not local or not domain:
        return text
    return local + "@" + domain


def email_of(record):
    return fold(record.get("email"))


def emails_of(user):
    """A directory user's addresses: email and alternateEmail, folded."""
    found = []
    for key in ["email", "alternateEmail"]:
        value = fold(user.get(key))
        if value and value not in found:
            found.append(value)
    return found


def domain_of(email):
    if email.count("@") != 1:
        return ""
    return email.split("@")[1]


def user_active(user):
    if truthy(user.get("suspended")):
        return False
    return str(user.get("state") or "").strip().upper() != "SUSPENDED"


def label(record):
    """An opaque record id; administrator emails are never copied into the output."""
    return str(record.get("_id") or record.get("id") or "unnamed")[:64]


def name_list(items):
    shown = ", ".join(items[:MAX_NAMED])
    if len(items) > MAX_NAMED:
        shown = shown + " and " + str(len(items) - MAX_NAMED) + " more"
    return shown


def not_evaluated(validation, reason, summary=None, findings=None):
    return create_response(
        result={KEY: None, "adminCount": None, "adminsSharingEverydayIdentity": None},
        validation=validation, api_errors=[reason],
        fail_reasons=["Admin account separation was not evaluated: " + reason],
        recommendations=["Confirm the JumpCloud API key can list every administrator (/api/users) and every "
                         "directory user (/api/systemusers) in full"],
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
        top = error_reason(data)
        if top:
            return not_evaluated(validation, top)
        if not isinstance(data, dict):
            return not_evaluated(validation, "no JumpCloud administrator and directory user lists in the response")

        admin_key, admin_block = pick(data, ADMIN_KEYS)
        user_key, user_block = pick(data, USER_KEYS)
        if admin_key is None or user_key is None:
            return not_evaluated(validation, "the response does not carry both the administrator list "
                                             "(administrators) and the directory user list (systemUsers)")

        admins, admin_problem = full_list(admin_block, "administrators")
        users, user_problem = full_list(user_block, "directory users")
        # The workflow's own markers (reportPagination): a list cut off before its last page.
        stats = data.get("paginationStats") if isinstance(data.get("paginationStats"), dict) else {}
        for key, what in [(admin_key, "administrators"), (user_key, "directory users")]:
            marker = stats.get(key) if isinstance(stats.get(key), dict) else {}
            if truthy(marker.get("paginationTruncated")):
                if what == "administrators" and not admin_problem:
                    admin_problem = "the administrators list was cut off before its last page"
                if what == "directory users" and not user_problem:
                    user_problem = "the directory users list was cut off before its last page"
        if truthy(data.get("paginationTruncated")) and not (admin_problem or user_problem):
            user_problem = "a list was cut off before its last page"

        # Who is an everyday identity, by email. Built from whatever was read, even a partial list:
        # a match found in a partial list is still a proven match.
        active_emails = {}
        suspended_emails = {}
        active_domains = {}
        active_users = 0
        user_records = 0
        for user in users or ((user_block or {}).get("results") if isinstance(user_block, dict) else None) or []:
            if not isinstance(user, dict):
                continue
            user_records = user_records + 1
            active = user_active(user)
            if active:
                active_users = active_users + 1
                # Domains from the primary email only; alternateEmail is often a personal address.
                primary_domain = domain_of(email_of(user))
                if primary_domain:
                    active_domains[primary_domain] = True
            for email in emails_of(user):
                if active:
                    active_emails[email] = True
                else:
                    suspended_emails[email] = True

        admin_rows = admins
        if admin_rows is None and isinstance(admin_block, dict) and isinstance(admin_block.get("results"), list):
            admin_rows = [a for a in admin_block.get("results") if isinstance(a, dict)]
        admin_rows = admin_rows or []
        active_admins = [a for a in admin_rows if not truthy(a.get("suspended"))]

        sharing = []
        suspended_match = []
        no_email = []
        off_domain = []
        dedicated = 0
        for admin in active_admins:
            email = email_of(admin)
            if not email:
                no_email.append(label(admin))
            elif email in active_emails:
                sharing.append(label(admin))
            elif domain_of(email) not in active_domains:
                # Not compared: no everyday directory user is on this domain. Never counted as dedicated.
                off_domain.append(label(admin))
            elif email in suspended_emails:
                suspended_match.append(label(admin))
                dedicated = dedicated + 1
            else:
                dedicated = dedicated + 1

        summary = {"administratorCount": len(admin_rows), "activeAdministratorCount": len(active_admins),
                   "suspendedAdministratorCount": len(admin_rows) - len(active_admins),
                   "directoryUserCount": user_records,
                   "activeDirectoryUserCount": active_users,
                   "administratorsOffDirectoryDomains": len(off_domain),
                   "dedicatedAdministratorCount": dedicated,
                   "administratorsSharingEverydayIdentity": len(sharing),
                   "administratorsWithoutEmail": len(no_email),
                   "affectedAccounts": sharing[:MAX_AFFECTED], "affectedAccountCount": len(sharing)}
        findings = []
        if len(admin_rows) > len(active_admins):
            findings.append(str(len(admin_rows) - len(active_admins)) + " administrator(s) are suspended (not judged)")
        if suspended_match:
            findings.append(str(len(suspended_match)) + " administrator(s) share an email with a SUSPENDED directory "
                            "user, so that everyday identity cannot sign in: " + name_list(suspended_match))

        if sharing:
            reason = (str(len(sharing)) + " of " + str(len(active_admins)) + " active JumpCloud administrator(s) "
                      "sign in to the Admin Portal with the email of an active everyday directory user, so the admin "
                      "account is the person's everyday identity (administrator record ids): " + name_list(sharing))
            if admin_problem or user_problem or no_email or off_domain:
                reason = reason + "; the read was also incomplete, so more may be affected"
            return create_response(
                result={KEY: False, "adminCount": len(active_admins), "adminsSharingEverydayIdentity": len(sharing)},
                validation=validation, fail_reasons=[reason],
                recommendations=["Give each administrator a dedicated admin-only address that no directory user "
                                 "carries, and remove Admin Portal access from everyday identities"],
                input_summary=summary, additional_findings=findings)

        if admin_problem:
            return not_evaluated(validation, admin_problem, summary, findings)
        if user_problem:
            return not_evaluated(validation, user_problem, summary, findings)
        if not active_admins:
            return not_evaluated(validation, "no active JumpCloud administrator was returned; every organisation "
                                             "has one, so the list cannot be complete", summary, findings)
        if no_email:
            return not_evaluated(validation, str(len(no_email)) + " administrator(s) carry no email, so they cannot "
                                 "be compared with the directory users: " + name_list(no_email), summary, findings)
        if active_users == 0:
            return not_evaluated(validation, "the JumpCloud directory has no active user, so no administrator can be "
                                 "compared with an everyday identity; separation cannot be shown from JumpCloud",
                                 summary, findings)
        if off_domain:
            return not_evaluated(validation, str(len(off_domain)) + " of " + str(len(active_admins)) + " active "
                                 "administrator(s) use an email domain no active directory user's primary email is on, "
                                 "so they cannot be compared with an everyday identity and separation cannot be shown "
                                 "for them (administrator record ids): " + name_list(off_domain), summary, findings)

        return create_response(
            result={KEY: True, "adminCount": len(active_admins), "adminsSharingEverydayIdentity": 0},
            validation=validation,
            pass_reasons=["All " + str(len(active_admins)) + " active JumpCloud administrator(s) were compared with "
                          "directory users on their email domain and use an admin-only identity that no active "
                          "everyday directory user carries"],
            input_summary=summary, additional_findings=findings)
    except Exception as e:
        message = "Transformation error: " + str(e)[:200]
        return create_response(
            result={KEY: None, "adminCount": None, "adminsSharingEverydayIdentity": None},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[message], api_errors=[message], fail_reasons=[message])
