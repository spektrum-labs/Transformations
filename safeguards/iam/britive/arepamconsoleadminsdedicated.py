"""
Transformation: arePAMConsoleAdminsDedicated
Vendor: Britive  |  Category: Identity and Access Management

CLAIM. The privileged access management console is administered only by dedicated admin
accounts, not by people's everyday SSO identities.

SOURCE. Method listUsers (already defined on the Britive integration):
  GET https://{tenant}.britive-app.com/api/users?type=User&page=0&size=100&...&filter=status eq active
  -> {"count", "page", "size", "data": [User]}
  User: userId, username, email, status, type, rootUser, adminRoles [{name}] (e.g. TenantAdmin),
        identityProvider {id, name, type}. type "DEFAULT" is Britive's own identity provider:
        the Britive SDK only allows a password reset for users whose identityProvider.type is
        "DEFAULT" (britive/python-sdk, identity_management/users.py); any other type (SAML,
        ...) is a federated sign-in through the customer's IdP.

RULE. Console administrators are the active users with a non-empty adminRoles list or
rootUser true (any Britive admin role administers some part of the console). Each must be a
dedicated admin account, which is either
  (a) LOCAL: identityProvider.type is "DEFAULT" (a Britive-native account, not the IdP), or
  (b) SEPARATELY NAMED: it signs in through a federated identity provider, but its username's
      first or last token is an admin marker (adm, admin, administrator, priv, tier0, t0),
      e.g. adm-jdoe or jdoe.admin -- a distinct IdP identity kept for admin work.
True when every administrator is (a) or (b). False when any administrator signs in through a
federated provider under an ordinary personal username: that is the person's everyday SSO
identity holding console admin.

FAIL CLOSED (None, dataCollection "error", never a pass): an empty body or error body; no
"data" list; a page that is not the whole population ("count" above the rows returned, or a
full page of "size" rows with no count); no administrator in the list; an administrator with
no identityProvider.type.
"""

import json
from datetime import datetime

CRITERIA_KEY = "arePAMConsoleAdminsDedicated"
#: An account name whose first or last token is one of these is a separately named admin
#: identity (adm-jdoe, jdoe.admin, admin_jdoe, t0-jdoe). Tokens split on . _ - and space,
#: after dropping any DOMAIN\\ prefix and @domain suffix. Matching is exact per token, so
#: "admiral" or "badminton" never count.
ADMIN_MARKERS = ("adm", "admin", "administrator", "priv", "tier0", "t0")
WRAPPERS = ["api_response", "response", "result", "apiResponse", "Output"]


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None,
                    api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    transform_err_list = transformation_errors or []
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if api_err_list else "success", "errors": api_err_list},
            "validation": {"status": validation.get("status", "unknown"),
                           "errors": validation.get("errors", []),
                           "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if transform_err_list else "success",
                               "errors": transform_err_list, "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                           "recommendations": recommendations or [],
                           "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "2.0",
                         "transformationId": TRANSFORM_ID, "vendor": VENDOR,
                         "category": "Identity and Access Management"},
        },
    }


def not_evaluated(reason, summary=None):
    return create_response(result={CRITERIA_KEY: None}, api_errors=[reason],
                           fail_reasons=["Not evaluated: " + reason], input_summary=summary or {})


def parse(value):
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        if text.startswith("<"):
            raise ValueError("HTML or XML body; expected JSON from the vendor API")
        return json.loads(text)
    return value


def unwrap(data):
    if isinstance(data, dict) and "data" in data and "validation" in data:
        data = data["data"]
    for depth in range(4):
        if not isinstance(data, dict):
            break
        moved = False
        for key in WRAPPERS:
            if isinstance(data.get(key), (dict, list)):
                data = data[key]
                moved = True
                break
        if not moved:
            break
    return data


def error_reason(data):
    """A reason when the body is a vendor or Integration-Service error, else None."""
    if not isinstance(data, dict):
        return None
    if data.get("error") is True:
        return "Integration-Service returned an error: " + str(data.get("message") or "")[:200]
    if data.get("success") is False:
        return "vendor reported success=false: " + str(data.get("message") or data.get("Message") or "")[:200]
    if data.get("errorCode") or data.get("ErrorCode"):
        return "vendor error " + str(data.get("errorCode") or data.get("ErrorCode"))[:120]
    if isinstance(data.get("error"), (dict, str)) and data.get("error"):
        return "error body: " + json.dumps(data.get("error"))[:200]
    for key in ("statusCode", "status_code", "httpStatus", "status"):
        code = data.get(key)
        if isinstance(code, int) and code >= 400:
            return "HTTP " + str(code)
    return None


def admin_marker(name):
    if not isinstance(name, str) or not name.strip():
        return False
    text = name.strip().lower()
    if "\\" in text:
        text = text.split("\\")[-1]
    if "@" in text:
        text = text.split("@")[0]
    for sep in (".", "_", "-", " "):
        text = text.replace(sep, "|")
    tokens = [t for t in text.split("|") if t]
    if not tokens:
        return False
    return tokens[0] in ADMIN_MARKERS or tokens[-1] in ADMIN_MARKERS


def judge(admins, summary):
    """admins: list of dicts {name, local, source}. Returns the response."""
    dedicated = []
    everyday = []
    for a in admins:
        if a["local"]:
            dedicated.append(a["name"] + " (local " + VENDOR + " account)")
        elif admin_marker(a["name"]):
            dedicated.append(a["name"] + " (separately named admin account via " + a["source"] + ")")
        else:
            everyday.append(a["name"] + " (signs in via " + a["source"] + ")")
    summary["consoleAdmins"] = len(admins)
    summary["dedicatedAdmins"] = len(dedicated)
    summary["everydayIdentityAdmins"] = len(everyday)
    if everyday:
        return create_response(
            result={CRITERIA_KEY: False, "consoleAdmins": len(admins), "everydayIdentityAdmins": len(everyday)},
            input_summary=summary,
            fail_reasons=[str(len(everyday)) + " of " + str(len(admins)) + " " + VENDOR
                          + " console administrator(s) sign in with a directory or SSO identity that is "
                          "not a separately named admin account: " + ", ".join(everyday[:20])],
            recommendations=["Give each " + VENDOR + " administrator a dedicated admin account (a local console "
                             "account, or a separate directory account named for admin use such as adm-<name>) "
                             "and remove administrator rights from everyday SSO identities"])
    return create_response(
        result={CRITERIA_KEY: True, "consoleAdmins": len(admins), "everydayIdentityAdmins": 0},
        input_summary=summary,
        pass_reasons=["All " + str(len(admins)) + " " + VENDOR + " console administrator(s) are dedicated "
                      "admin accounts: " + ", ".join(dedicated[:20])])


TRANSFORM_ID = "arepamconsoleadminsdedicated"
VENDOR = "Britive"


def transform(input):
    try:
        data = unwrap(parse(input))
        if data is None or data == {} or data == []:
            return not_evaluated("empty response: no Britive users were read")
        reason = error_reason(data)
        if reason:
            return not_evaluated(reason)
        if not isinstance(data, dict) or not isinstance(data.get("data"), list):
            return not_evaluated("no users list (data) in the response")
        users = data["data"]
        count = data.get("count")
        size = data.get("size")
        if isinstance(count, int) and count > len(users):
            return not_evaluated("only " + str(len(users)) + " of " + str(count)
                                 + " users were returned: the list is partial")
        if not isinstance(count, int) and isinstance(size, int) and size > 0 and len(users) >= size:
            return not_evaluated("a full page of " + str(size) + " users with no total count: the list may be partial")
        admins = []
        for u in users:
            if not isinstance(u, dict):
                continue
            if str(u.get("status") or "active").strip().lower() != "active":
                continue
            if str(u.get("type") or "User") != "User":
                continue
            roles = u.get("adminRoles")
            role_names = []
            if isinstance(roles, list):
                role_names = [str(r.get("name")) for r in roles if isinstance(r, dict) and r.get("name")]
            if not role_names and u.get("rootUser") is not True:
                continue
            name = str(u.get("username") or u.get("email") or u.get("userId"))
            idp = u.get("identityProvider")
            idp_type = str(idp.get("type") or "").strip() if isinstance(idp, dict) else ""
            if not idp_type:
                return not_evaluated("administrator " + name + " has no identityProvider.type")
            idp_label = idp_type + " identity provider" + (
                " " + str(idp.get("name")) if idp.get("name") else "")
            admins.append({"name": name, "local": idp_type.upper() == "DEFAULT", "source": idp_label})
        summary = {"users": len(users), "count": count}
        if not admins:
            return not_evaluated("no user with a Britive admin role (adminRoles) or rootUser was "
                                 "returned, so the administrator population was not read", summary)
        return judge(admins, summary)
    except Exception as error:
        return create_response(result={CRITERIA_KEY: None}, transformation_errors=[str(error)],
                               api_errors=["transformation error: " + str(error)[:200]],
                               fail_reasons=["Not evaluated: " + str(error)[:200]])
