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
# An affected admin has no ACTIVE FIDO2/WebAuthn (webauthn) or FIDO U2F security key (u2f) factor. Push, SMS,
# TOTP and every other factor do not count. Okta lists only the factors the highest-priority enrollment policy
# allows (evaluated for the calling admin), so the line says a key enrolled outside it is not shown.
# Fails closed on the naming only: a per-admin result that is missing, an error (403/429/5xx arrive as
# {"vendorErrorAsResponse": ...}), out of line with the admin list, or for another user names no one and says
# the account read was partial. Same shape as #891 / #899 / #905: the first reason names at most MAX_NAMED, then
# "and N more"; inputSummary.affectedAccounts carries at most MAX_AFFECTED, with the full count in
# affectedAccountCount. The verdict never reads any of this, and without adminAssignees (today's workflow) the
# output is exactly what it was.
ADMIN_PHISH_RESISTANT_TYPES = ["webauthn", "u2f"]
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
            + " admins have no ACTIVE phishing-resistant factor (FIDO2/WebAuthn or FIDO U2F security key) enrolled ("
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
    """Adds the line to the first reason and the names to inputSummary. Verdict fields are not touched."""
    if named is None:
        return response
    accounts = named["accounts"]
    info = response["additionalInfo"]
    evaluation = info["evaluation"]
    if accounts["read"]:
        summary = info["transformation"]["inputSummary"]
        summary["affectedAccounts"] = accounts["affected"][:MAX_AFFECTED]
        summary["affectedAccountCount"] = len(accounts["affected"])
    if evaluation["failReasons"]:
        reasons = evaluation["failReasons"]
        reasons[0] = reasons[0] + "; " + named["line"]
    elif passed and evaluation["passReasons"] and (not accounts["read"] or accounts["affected"]
                                                    or accounts["capped"]):
        reasons = evaluation["passReasons"]
        reasons[0] = reasons[0] + "; " + named["line"]
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


def transform(input):
    data, validation = extract_input(input)
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
