"""
Transformation: isAdminMFAPhishingResistant
Vendor: Okta   Method: GET /api/v1/org/factors (listOrgFactors: every factor the org can enroll, with status)

Requirement asked: "Only phishing-resistant factors for admins are permitted."

What the org factor list can and cannot prove:
- No phishing-resistant factor ACTIVE  -> admins cannot be limited to phishing-resistant MFA: False.
- Phishing-resistant factors ACTIVE and NO phishable factor ACTIVE -> the org permits only
  phishing-resistant factors, so admins too: True.
- Phishing-resistant AND phishable factors ACTIVE -> whether admins are restricted is decided by the
  Admin Console authentication policy, which this response does not carry: None (not evaluated).
- Anything that is not a factor list (null, {}, [], an error envelope, unrelated JSON): None, with
  additionalInfo.dataCollection.status "error", so a failed read is never scored.

Phishing-resistant factor types (Okta "Factors" API factorType values): webauthn (FIDO2 / WebAuthn),
u2f (FIDO U2F security key), signed_nonce (Okta FastPass), smart_card (PIV / CAC). Every other type
(push, sms, call, email, question, token:software:totp, token:hotp, token, token:hardware OTP, web)
can be relayed by a real-time phishing proxy.
Numbers: phishResistantActiveCount, phishableActiveCount.

Named accounts (#101): when the workflow also merges the per-admin reads (adminAssignees, adminUsers,
adminFactors; see ADMIN READS below) next to the org factor list (factors), the first reason and inputSummary
name the admins with no ACTIVE phishing-resistant factor enrolled. The verdict is unchanged.
"""
import json
from datetime import datetime


def extract_input(input_data):
    """Extract data and validation from input, handling enriched + legacy formats."""
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for _ in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    validation = {
        "status": "unknown",
        "errors": [],
        "warnings": ["Legacy input format - no schema validation performed"],
    }
    return data, validation


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None,
                    transformation_errors=None, api_errors=None, additional_findings=None):
    """Create the standardized 5-section transformation response."""
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    transform_err_list = transformation_errors or []
    data_collection_status = "error" if api_err_list else "success"
    transformation_status = "error" if transform_err_list else "success"
    response_metadata = {
        "evaluatedAt": datetime.utcnow().isoformat() + "Z",
        "schemaVersion": "2.0",
    }
    if metadata:
        response_metadata.update(metadata)
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": data_collection_status, "errors": api_err_list},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": transformation_status,
                "errors": transform_err_list,
                "inputSummary": input_summary or {},
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or [],
            },
            "metadata": response_metadata,
        },
    }


PHISH_RESISTANT_TYPES = ["webauthn", "u2f", "signed_nonce", "smart_card"]
FACTOR_STATUSES = ["ACTIVE", "INACTIVE", "NOT_SETUP", "PENDING_ACTIVATION"]
KEY = "isAdminMFAPhishingResistant"

# ADMIN READS (#101). The isAdminMFAPhishingResistantAccounts workflow merges, next to the org factor list
# (factors), three per-admin reads:
#   adminAssignees  GET /api/v1/iam/assignees/users?limit=100, one page: {"value": [{"id": ...}], "_links": ...}
#                   (okta.roles.read; ids only). A next page left unread is marked by IS as
#                   _links.next = {"href": null, "truncated": true}, so more than 100 admins read as capped.
#   adminUsers      GET /api/v1/users/{id} per admin, in admin order (for the login)
#   adminFactors    GET /api/v1/users/{id}/factors per admin, in admin order (okta.users.read; not paginated)
# Docs: https://developer.okta.com/docs/api/openapi/okta-management/management/tag/RoleAssignmentBUser/
#       https://developer.okta.com/docs/api/openapi/okta-management/management/tag/UserFactor/
# An affected admin has no ACTIVE factor of a PHISH_RESISTANT_TYPES type (webauthn, u2f, signed_nonce, smart_card:
# the set the verdict counts). Push, SMS, TOTP and every other factor do not count. Okta lists only the factors the highest-priority enrollment policy
# allows (evaluated for the calling admin), so the line says a key enrolled outside it is not shown.
# Fails closed on the naming only: a per-admin result that is missing, an error (403/429/5xx arrive as
# {"vendorErrorAsResponse": ...}), out of line with the admin list, or for another user names no one and says
# the account read was partial. Same shape as #891 / #899 / #905: the first reason names at most MAX_NAMED, then
# "and N more"; inputSummary.affectedAccounts carries at most MAX_AFFECTED, with the full count in
# affectedAccountCount. The verdict never reads any of this, and without adminAssignees (today's workflow) the
# output is exactly what it was.
ADMIN_PHISH_RESISTANT_TYPES = PHISH_RESISTANT_TYPES  # the verdict's own set, so the two cannot drift
MAX_NAMED = 20
MAX_AFFECTED = 50
ADMIN_CAP = 100
ACCOUNT_SCOPE = "Okta (users holding an Okta admin role)"


def read_error(block):
    """A short reason when a read came back as an error instead of data, else None."""
    if not isinstance(block, dict):
        return None
    marked = block.get("vendorErrorAsResponse")
    if isinstance(marked, dict):
        return "Okta answered HTTP " + str(marked.get("status"))[:8]
    if block.get("error") or block.get("errorCode"):
        return "the read returned an error"
    return None


def admin_list_capped(block):
    links = block.get("_links")
    nxt = links.get("next") if isinstance(links, dict) else None
    if not isinstance(nxt, dict):
        return False
    return nxt.get("truncated") is True or bool(nxt.get("href"))


def factor_belongs(fac, admin_id):
    """False when a factor's own links point at another user (the per-admin results are out of line)."""
    links = fac.get("_links")
    if not isinstance(links, dict):
        return True
    for name in ("self", "user"):
        link = links.get(name)
        href = link.get("href") if isinstance(link, dict) else None
        if isinstance(href, str) and "/users/" in href and ("/users/" + admin_id + "/") not in (href + "/"):
            return False
    return True


def login_of(user, admin_id):
    profile = user.get("profile") if isinstance(user.get("profile"), dict) else {}
    name = profile.get("login") or profile.get("email") or admin_id
    return str(name).strip()[:100]


def partial(why):
    return {"read": False, "partial": True, "why": why}


def admin_accounts(data):
    """None when the per-admin reads are not in the input; otherwise who is affected, or why no one is named."""
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except Exception:
            return None
    if not isinstance(data, dict) or "adminAssignees" not in data:
        return None
    block = data.get("adminAssignees")
    err = read_error(block)
    if err:
        return {"read": False, "partial": False, "why": "the admin role assignments were not read (" + err + ")"}
    rows = block.get("value") if isinstance(block, dict) else None
    if not isinstance(rows, list):
        return {"read": False, "partial": False, "why": "the admin role assignments were not read"}
    if not rows:
        return {"read": False, "partial": False, "why": "Okta returned no admin role assignments"}
    ids = []
    for row in rows:
        admin_id = row.get("id") if isinstance(row, dict) else None
        if not isinstance(admin_id, str) or not admin_id.strip():
            return partial("an admin role assignment carries no user id")
        ids.append(admin_id.strip())
    users = data.get("adminUsers")
    factors = data.get("adminFactors")
    if not isinstance(users, list) or not isinstance(factors, list):
        return partial("the per-admin user or factor results are missing")
    if len(users) != len(ids) or len(factors) != len(ids):
        return partial("per-admin results for " + str(min(len(users), len(factors))) + " of " + str(len(ids))
                       + " admins")
    affected = []
    phishable_only = 0
    no_factor = 0
    for i in range(len(ids)):
        admin_id = ids[i]
        user = users[i]
        if read_error(user) or not isinstance(user, dict) or str(user.get("id") or "").strip() != admin_id:
            return partial("an admin's user record was not read")
        listed = factors[i]
        if not isinstance(listed, list):
            return partial("an admin's factor list was not read")
        resistant = False
        active = 0
        for fac in listed:
            if not isinstance(fac, dict) or not factor_belongs(fac, admin_id):
                return partial("an admin's factor list does not belong to that admin")
            if fac.get("status") == "ACTIVE":
                active = active + 1
                if fac.get("factorType") in ADMIN_PHISH_RESISTANT_TYPES:
                    resistant = True
        if not resistant:
            affected.append(login_of(user, admin_id))
            if active:
                phishable_only = phishable_only + 1
            else:
                no_factor = no_factor + 1
    return {"read": True, "partial": False, "total": len(ids), "affected": affected,
            "phishableOnly": phishable_only, "noFactor": no_factor, "capped": admin_list_capped(block)}


def name_list(items):
    """At most MAX_NAMED identifiers, then 'and N more'."""
    shown = ", ".join(items[:MAX_NAMED])
    if len(items) > MAX_NAMED:
        shown = shown + " and " + str(len(items) - MAX_NAMED) + " more"
    return shown


def accounts_line(accounts):
    """One line naming the tool and its scope."""
    if not accounts["read"]:
        if accounts["partial"]:
            return (ACCOUNT_SCOPE + ": accounts not named, the per-admin account read was partial ("
                    + accounts["why"] + ")")
        return ACCOUNT_SCOPE + ": accounts not named, " + accounts["why"]
    line = (ACCOUNT_SCOPE + ": " + str(len(accounts["affected"])) + " of " + str(accounts["total"])
            + " admins have no ACTIVE phishing-resistant factor (FIDO2/WebAuthn, FIDO U2F, Okta FastPass or "
            + "smart card) enrolled ("
            + str(accounts["phishableOnly"]) + " with only phishable factors such as push, "
            + str(accounts["noFactor"]) + " with no active factor)")
    if accounts["affected"]:
        line = line + ": " + name_list(accounts["affected"])
    notes = []
    if accounts["capped"]:
        notes.append("the account read is partial: the admin list is capped at " + str(ADMIN_CAP)
                     + " and more admins exist, so more may be affected")
    if accounts["affected"]:
        notes.append("Okta lists only factors its enrollment policy allows, so a key enrolled outside it is not shown")
    if notes:
        line = line + "; " + "; ".join(notes)
    return line


def named_accounts(data):
    """Never lets the naming change the verdict: any surprise here names no one."""
    try:
        accounts = admin_accounts(data)
        if accounts is None:
            return None
        return {"accounts": accounts, "line": accounts_line(accounts)}
    except Exception:
        return None


def with_accounts(response, named, passed):
    """Adds the line to the first reason and the names to inputSummary. Verdict fields are not touched.

    Never lets the naming change the verdict: every lookup and type check runs before the first write, and any
    surprise returns the response exactly as it came in.
    """
    try:
        if named is None:
            return response
        accounts = named["accounts"]
        line = named["line"]
        evaluation = response["additionalInfo"]["evaluation"]
        summary = response["additionalInfo"]["transformation"]["inputSummary"]
        fail_reasons = evaluation["failReasons"]
        pass_reasons = evaluation["passReasons"]
        if not isinstance(summary, dict) or not isinstance(fail_reasons, list) or not isinstance(pass_reasons, list):
            return response
        if not isinstance(line, str):
            return response
        reasons = None
        if fail_reasons:
            reasons = fail_reasons
        elif passed and pass_reasons and (not accounts["read"] or accounts["affected"] or accounts["capped"]):
            reasons = pass_reasons
        if reasons is not None and not isinstance(reasons[0], str):
            return response
        affected = None
        if accounts["read"]:
            affected = list(accounts["affected"])
        if affected is not None:
            summary["affectedAccounts"] = affected[:MAX_AFFECTED]
            summary["affectedAccountCount"] = len(affected)
        if reasons is not None:
            reasons[0] = reasons[0] + "; " + line
        return response
    except Exception:
        return response


def factor_list(data):
    """Return the org factor list, or None when the body is not one."""
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except Exception:
            return None
    if isinstance(data, dict):
        for k in ("apiResponse", "factors", "rawResponse", "data"):
            if isinstance(data.get(k), list):
                data = data[k]
                break
    if not isinstance(data, list) or not data:
        return None
    for f in data:
        if not isinstance(f, dict) or not f.get("factorType") or f.get("status") not in FACTOR_STATUSES:
            return None
    return data


def unevaluated_response(validation, message, summary=None):
    return create_response(
        result={KEY: None, "phishResistantActiveCount": None, "phishableActiveCount": None},
        validation=validation,
        api_errors=[message],
        fail_reasons=[message],
        input_summary=summary or {},
        metadata={"transformationId": KEY, "vendor": "Okta", "category": "iam"},
    )


# --- COVERAGE OF ADMINISTRATORS (getAdminAuthenticatorPosture) ----------------------------------
#
# Product decision, Josh, 5 Oct 2026: this criterion is an ENFORCEMENT claim about administrator
# accounts, reported as a coverage percentage, and it FAILS below 100%. That keeps the requirement's
# existing `isEquals true` working with no requirement change; customer-set thresholds arrive in the
# next platform version. An enforcement surface that cannot be read answers "not evaluated".
#
# Body: the Integration-Service workflow getAdminAuthenticatorPosture merges
#   adminAssignees    GET /api/v1/iam/assignees/users -- {"value": [{"id": ...}, ...], "_links": ...},
#                     paged by the body's _links.next.href; with reportPagination it also sets
#                     paginationStats.adminAssignees.paginationTruncated (always present when this IS
#                     build can tell) and top-level paginationTruncated when the list was cut off.
#   adminEnrollments  GET /api/v1/users/{id}/authenticator-enrollments per admin, INDEX-ALIGNED with
#                     adminAssignees.value. With continueOnItemError a failed read is the record
#                     {"error": true, "statusCode": ..., "item": "<userId>", "errorType": ...}; with
#                     maxItems the list stops at the cap and iterateTruncated is set.
#
# Why /authenticator-enrollments and not /users/{id}/factors: Okta documents the latter as listing
# only factors in the HIGHEST PRIORITY enrollment policy, evaluated against the CALLING admin's
# client and network zone rather than the user's. A percentage built on it would vary by caller.
#
# Each admin is one of:
#   covered        an ACTIVE enrollment that is phishing-resistant
#   indeterminate  no such enrollment, but an ACTIVE one that may or may not be (see below)
#   noActive       no ACTIVE enrollment at all. Okta keeps admin roles on SUSPENDED and DEPROVISIONED
#                  users, who cannot sign in and often hold no ACTIVE enrollment, and an empty list from
#                  a call that otherwise succeeded is also what a scope or policy filter looks like. It is
#                  therefore never counted as uncovered: it blocks a 100% claim (not evaluated) and is
#                  reported as adminsWithNoActiveEnrollment, until the workflow reads user status.
#   uncovered      ACTIVE enrollments, every one of them a known phishable authenticator
#   unreadable     the slot is an error, not an enrollment list, belongs to another user, carries an
#                  enrollment whose status is not a documented value, or its admin row has no id
# One uncovered admin PROVES coverage is below 100%, so the verdict is False even when other reads
# were partial. 100% can only be claimed from a complete read with no indeterminate or noActive admin.
# The per-admin slots are paired with adminAssignees.value BY INDEX. When the pairing cannot be trusted
# (more slots than admins, fewer without a read cap, iterateStats.itemsTotal that disagrees, an item error
# naming another user, or an enrollment whose links name another user) there is no verdict at all, because
# every later admin would be scored against someone else's enrollments.
# transformedResponse carries the percentage only when it is exact (complete read, no indeterminate or
# noActive admin); otherwise it is None there and the partial figure is kept in inputSummary for display.
COVERAGE_KEY = "adminPhishResistantCoveragePercentage"
ENROLLMENT_STATUSES = ["ACTIVE", "INACTIVE", "PENDING_ACTIVATION"]
# webauthn (FIDO2 / passkeys) and smart_card_idp (PIV / CAC) are phishing-resistant.
# okta_verify_fastpass is the per-method FastPass authenticator (Flexible Okta Verify EA): signed
# nonce, treated as phishing-resistant here exactly as PHISH_RESISTANT_TYPES treats signed_nonce.
COVERAGE_RESISTANT_KEYS = ["webauthn", "smart_card_idp", "okta_verify_fastpass"]
# okta_verify is the legacy aggregate: Okta does not say whether that enrollment is FastPass or
# push, so it cannot be called either. security_key has its own schema and was not verified to be
# FIDO rather than OTP. Neither is counted as covered or as uncovered.
COVERAGE_UNKNOWN_KEYS = ["okta_verify", "security_key"]
# Known PHISHABLE authenticators (password, email, SMS/voice, security question, OTP apps and tokens,
# RADIUS/on-prem OTP). An admin is "uncovered" only when every ACTIVE enrollment is one of these.
# Any other key (duo, external_idp, custom_app, or one Okta adds later) cannot be called either way,
# so it makes the admin indeterminate: unclear data reads "not evaluated", never a fail.
COVERAGE_PHISHABLE_KEYS = ["okta_password", "okta_email", "phone_number", "security_question", "google_otp",
                           "yubikey_token", "rsa_token", "symantec_vip", "custom_otp", "onprem_mfa"]


def is_item_error(entry):
    return isinstance(entry, dict) and entry.get("error") is True


def enrollment_list(entry):
    """One admin's enrollments, or None when the slot is not an enrollment list."""
    if isinstance(entry, list):
        return [e for e in entry if isinstance(e, dict)]
    if isinstance(entry, dict):
        for wrap in ("value", "data", "apiResponse"):
            if isinstance(entry.get(wrap), list):
                return [e for e in entry.get(wrap) if isinstance(e, dict)]
    return None


def classify_admin(enrollments):
    if any(str(e.get("status") or "").upper() not in ENROLLMENT_STATUSES for e in enrollments):
        return "unreadable"
    active = [str(e.get("key") or "").lower() for e in enrollments
              if str(e.get("status") or "").upper() == "ACTIVE"]
    if not active:
        return "noActive"
    if any(k in COVERAGE_RESISTANT_KEYS for k in active):
        return "covered"
    if any(k in COVERAGE_UNKNOWN_KEYS or k not in COVERAGE_PHISHABLE_KEYS for k in active):
        return "indeterminate"
    return "uncovered"


def misalignment(data, rows, enrollments, reads_cut):
    """Why the index pairing of admins and enrollment slots cannot be trusted, or None when it can."""
    if len(enrollments) > len(rows):
        return str(len(enrollments)) + " enrollment results for " + str(len(rows)) + " admins"
    if reads_cut is not True:
        if len(enrollments) < len(rows):
            return str(len(enrollments)) + " enrollment results for " + str(len(rows)) + " admins with no read cap"
        stats = data.get("iterateStats")
        block = stats.get("adminEnrollments") if isinstance(stats, dict) else None
        total = block.get("itemsTotal") if isinstance(block, dict) else None
        if isinstance(total, int) and not isinstance(total, bool) and total != len(rows):
            return "the workflow iterated " + str(total) + " admins but listed " + str(len(rows))
    for index, entry in enumerate(enrollments):
        row = rows[index]
        admin_id = str(row.get("id") or "").strip() if isinstance(row, dict) else ""
        if not admin_id:
            continue
        if is_item_error(entry):
            item = entry.get("item")
            if isinstance(item, str) and item.strip() and item.strip() != admin_id:
                return "a failed read names a different user than the admin in its position"
            continue
        listed = enrollment_list(entry) if not read_error(entry) else None
        if listed and not all(factor_belongs(e, admin_id) for e in listed):
            return "an enrollment links to a different user than the admin in its position"
    return None


def flag(data, top_key, stats_key, output_key):
    """True / False from a workflow marker, or None when this IS build did not report it."""
    if data.get(top_key) is True:
        return True
    stats = data.get(stats_key)
    block = stats.get(output_key) if isinstance(stats, dict) else None
    if isinstance(block, dict) and isinstance(block.get(top_key), bool):
        return block.get(top_key)
    return None


def coverage_response(data, validation):
    block = data.get("adminAssignees")
    rows = block.get("value") if isinstance(block, dict) else (block if isinstance(block, list) else None)
    if isinstance(block, dict) and read_error(block):
        rows = None
    if not isinstance(rows, list):
        return unevaluated_response(
            validation, "The admin role assignments (GET /api/v1/iam/assignees/users) were not read, so "
                        "phishing-resistant MFA coverage of administrators was not evaluated. The integration "
                        "needs the okta.roles.read scope.")
    if not rows:
        return unevaluated_response(
            validation, "Okta returned no users holding an admin role, so there is no administrator "
                        "population to measure.")

    enrollments = data.get("adminEnrollments")
    if not isinstance(enrollments, list):
        return unevaluated_response(
            validation, "The administrators' authenticator enrollments were not read, so phishing-resistant "
                        "MFA coverage of administrators was not evaluated.")

    list_cut = flag(data, "paginationTruncated", "paginationStats", "adminAssignees")
    reads_cut = flag(data, "iterateTruncated", "iterateStats", "adminEnrollments")
    misaligned = misalignment(data, rows, enrollments, reads_cut)
    if misaligned:
        return unevaluated_response(
            validation, "The administrators' enrollment reads are out of line with the admin list (" + misaligned
                        + "), so no enrollment can be matched to its administrator and coverage was not evaluated.",
            {"adminsListed": len(rows), "enrollmentSlots": len(enrollments)})

    covered, indeterminate, no_active, uncovered, unreadable = 0, 0, 0, 0, 0
    uncovered_ids = []
    for index, row in enumerate(rows):
        full_id = str(row.get("id") or "").strip() if isinstance(row, dict) else ""
        admin_id = full_id[:64]
        if not full_id:
            unreadable = unreadable + 1
            continue
        entry = enrollments[index] if index < len(enrollments) else None
        listed = None if (entry is None or is_item_error(entry) or read_error(entry)) else enrollment_list(entry)
        state = "unreadable" if listed is None else classify_admin(listed)
        if state == "unreadable":
            unreadable = unreadable + 1
        elif state == "covered":
            covered = covered + 1
        elif state == "indeterminate":
            indeterminate = indeterminate + 1
        elif state == "noActive":
            no_active = no_active + 1
        else:
            uncovered = uncovered + 1
            if len(uncovered_ids) < MAX_AFFECTED:
                uncovered_ids.append(admin_id)

    assessed = covered + indeterminate + no_active + uncovered
    complete = list_cut is False and reads_cut is not True and unreadable == 0
    exact = complete and indeterminate == 0 and no_active == 0
    # Floored, so only a true 100% reads as 100 (1 uncovered of 2,000 is 99.9, not 100.0).
    pct = ((1000 * covered) // assessed) / 10.0 if assessed else None

    summary = {"adminsListed": len(rows), "adminsAssessed": assessed, "adminsCovered": covered,
               "adminsIndeterminate": indeterminate, "adminsWithNoActiveEnrollment": no_active,
               "adminsUncovered": uncovered, "adminsUnreadable": unreadable, "adminListComplete": list_cut is False,
               "enrollmentReadsCapped": reads_cut is True, COVERAGE_KEY: pct, "adminCoverageComplete": exact,
               "uncoveredAdminIds": uncovered_ids}
    result = {KEY: None, COVERAGE_KEY: pct if exact else None, "adminsAssessed": assessed, "adminsCovered": covered}

    if uncovered:
        result[KEY] = False
        partial_note = "" if complete else (" Not every administrator could be read, so coverage of the "
                                            "full population may be lower still.")
        return create_response(
            result=result, validation=validation,
            fail_reasons=[f"{uncovered} of {assessed} administrators assessed have no ACTIVE "
                          f"phishing-resistant authenticator (FIDO2/WebAuthn, smart card or Okta FastPass) "
                          f"enrolled; coverage is {pct}%." + partial_note],
            recommendations=["Enroll every administrator in FIDO2/WebAuthn or Okta FastPass, then require a "
                             "phishing-resistant authenticator in the Okta Admin Console authentication policy."],
            input_summary=summary,
            metadata={"transformationId": KEY, "vendor": "Okta", "category": "iam"})

    if not exact:
        whys = []
        if indeterminate:
            whys.append(f"{indeterminate} administrator(s) have only Okta Verify, a security key or another "
                        f"authenticator Okta does not classify enrolled, so whether that enrollment is "
                        f"phishing-resistant (FastPass) or not (push/OTP) is unknown")
        if no_active:
            whys.append(f"{no_active} administrator(s) have no ACTIVE authenticator enrollment (often a suspended or "
                        f"deactivated user who still holds an admin role), which this read cannot tell apart from "
                        f"an enrollment list it was not allowed to see")
        if list_cut is None:
            whys.append("this Integration-Service build did not report whether the admin list was read in full")
        elif list_cut:
            whys.append("the admin role assignment list was cut off before its last page")
        if reads_cut is True:
            whys.append("the per-admin enrollment reads were capped before every administrator was read")
        if unreadable:
            whys.append(f"{unreadable} administrator(s)' enrollments could not be read")
        if not assessed:
            lead = "No administrator's enrollments could be assessed"
        elif covered == assessed:
            lead = (f"Every administrator assessed ({covered} of {assessed}) has a phishing-resistant "
                    f"authenticator")
        else:
            lead = (f"{covered} of {assessed} administrators assessed have a phishing-resistant authenticator and "
                    f"none is known to lack one")
        response = unevaluated_response(
            validation, lead + ", but 100% coverage cannot be confirmed: " + "; ".join(whys) + ".", summary)
        response["transformedResponse"]["adminsAssessed"] = assessed
        response["transformedResponse"]["adminsCovered"] = covered
        return response

    result[KEY] = True
    return create_response(
        result=result, validation=validation,
        pass_reasons=[f"All {assessed} administrators have an ACTIVE phishing-resistant authenticator "
                      f"(FIDO2/WebAuthn, smart card or Okta FastPass) enrolled; coverage is 100%."],
        input_summary=summary,
        metadata={"transformationId": KEY, "vendor": "Okta", "category": "iam"})


def transform(input):
    data, validation = extract_input(input)
    if isinstance(data, dict) and "adminEnrollments" in data:
        response = coverage_response(data, validation)
        # Every coverage return carries the same keys: a threshold token must meet None, never a missing key.
        result = response["transformedResponse"]
        for k in (COVERAGE_KEY, "adminsAssessed", "adminsCovered"):
            if k not in result:
                result[k] = None
        return response
    factors = factor_list(data)
    if factors is None:
        return unevaluated_response(validation, "No Okta org factor list in the response (GET /api/v1/org/factors); "
                                        "phishing-resistant MFA for admins cannot be judged.")

    active = [f for f in factors if f.get("status") == "ACTIVE"]
    resistant = [f"{f.get('factorType')}/{f.get('provider') or ''}" for f in active
                 if f.get("factorType") in PHISH_RESISTANT_TYPES]
    phishable = [f"{f.get('factorType')}/{f.get('provider') or ''}" for f in active
                 if f.get("factorType") not in PHISH_RESISTANT_TYPES]
    summary = {"totalFactors": len(factors), "activeFactorCount": len(active),
               "phishResistantActiveCount": len(resistant), "phishableActiveCount": len(phishable)}

    named = named_accounts(data)
    if resistant and phishable:
        return with_accounts(unevaluated_response(
            validation,
            f"Phishing-resistant factor(s) {', '.join(resistant)} and phishable factor(s) {', '.join(phishable)} "
            f"are both ACTIVE. Whether admins are limited to the phishing-resistant ones is set by the Admin "
            f"Console authentication policy, which the org factor list does not show.",
            summary,
        ), named, False)

    passed = bool(resistant)
    pass_reasons, fail_reasons, recommendations = [], [], []
    if passed:
        pass_reasons.append(f"Only phishing-resistant factors are ACTIVE in the org ({', '.join(resistant)}), "
                            f"so admins can authenticate only with phishing-resistant MFA.")
    else:
        fail_reasons.append(f"No phishing-resistant factor (FIDO2/WebAuthn, FIDO U2F, Okta FastPass, smart card) is "
                            f"ACTIVE; active factors: {', '.join(phishable) or 'none'}. Admins cannot be limited to "
                            f"phishing-resistant MFA.")
        recommendations.append("Activate FIDO2 (WebAuthn) or Okta FastPass and require a phishing-resistant "
                               "authenticator in the Okta Admin Console authentication policy.")

    return with_accounts(create_response(
        result={KEY: passed, "phishResistantActiveCount": len(resistant), "phishableActiveCount": len(phishable),
                "activePhishResistantFactors": resistant, "activeFactorTypes": resistant + phishable},
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=summary,
        metadata={"transformationId": KEY, "vendor": "Okta", "category": "iam"},
    ), named, passed)
