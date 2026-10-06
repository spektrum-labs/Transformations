"""
Transformation: arePAMConsoleAdminsDedicated
Vendor: BeyondTrust Privileged Remote Access (also Remote Support: same Configuration API)
Category: Identity and Access Management

CLAIM. The privileged access management console is administered only by dedicated admin
accounts, not by people's everyday SSO identities.

SOURCE. Workflow getConsoleAdmins, two legs under their own output keys:
  users              <- getUsers             GET {serverUrl}/api/config/v1/user
  securityProviders  <- getSecurityProviders GET {serverUrl}/api/config/v1/security-provider
  User: id, username, enabled, perm_admin (the "Administrator" permission, read-only),
        security_provider_id (the provider through which the user authenticates).
  SecurityProvider: id, name, type in local | ldap | radius | kerberos | saml | scim.
  https://docs.beyondtrust.com/pra/reference/apiconfiguserindex
  https://docs.beyondtrust.com/pra/reference/apiconfigsecurity-providerindex

RULE. Console administrators are the enabled users with perm_admin true. Each must be a
dedicated admin account, which is either
  (a) LOCAL: its security provider has type "local" (credentials held by the appliance, not
      the directory or IdP), or
  (b) SEPARATELY NAMED: it signs in through ldap/radius/kerberos/saml/scim, but its username's
      first or last token is an admin marker (adm, admin, administrator, priv, tier0, t0),
      e.g. adm-jdoe or jdoe.admin -- a distinct directory identity kept for admin work.
True when every administrator is (a) or (b). False when any administrator signs in through a
directory or SSO provider under an ordinary personal username: that is the person's everyday
identity holding console admin.

FAIL CLOSED (None, dataCollection "error", never a pass): either leg missing or an error body;
no enabled administrator in the user list (an appliance always has one, so the read is
partial); an administrator with no security_provider_id or one that names a provider the
providers leg does not list; a users leg of exactly 100 records with no sign it was paged
(the API's page size, so the list may be truncated).
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
VENDOR = "BeyondTrust PRA"
PAGE_SIZE = 100


def as_list(leg):
    if isinstance(leg, list):
        return leg
    if isinstance(leg, dict):
        for key in ("data", "items", "results", "records", "users", "securityProviders"):
            if isinstance(leg.get(key), list):
                return leg[key]
    return None


def transform(input):
    try:
        data = unwrap(parse(input))
        if data is None or data == {} or data == []:
            return not_evaluated("empty response: no users or security providers were read")
        reason = error_reason(data)
        if reason:
            return not_evaluated(reason)
        if not isinstance(data, dict) or "users" not in data or "securityProviders" not in data:
            return not_evaluated("the users and securityProviders legs were not both returned")
        for leg_name in ("users", "securityProviders"):
            leg_error = error_reason(data.get(leg_name))
            if leg_error:
                return not_evaluated(leg_name + ": " + leg_error)
        users = as_list(data.get("users"))
        providers = as_list(data.get("securityProviders"))
        if users is None or providers is None:
            return not_evaluated("users or securityProviders is not a list")
        if len(users) == PAGE_SIZE:
            return not_evaluated("exactly " + str(PAGE_SIZE) + " users returned, the API page size: "
                                 "the list may be truncated")
        provider_by_id = {}
        for p in providers:
            if isinstance(p, dict) and p.get("id") is not None:
                provider_by_id[str(p.get("id"))] = p
        admins = []
        for u in users:
            if not isinstance(u, dict) or u.get("perm_admin") is not True:
                continue
            if u.get("enabled") is False:
                continue
            name = str(u.get("username") or u.get("public_display_name") or u.get("id"))
            pid = u.get("security_provider_id")
            if pid is None:
                return not_evaluated("administrator " + name + " has no security_provider_id")
            provider = provider_by_id.get(str(pid))
            if provider is None:
                return not_evaluated("administrator " + name + " uses security provider " + str(pid)
                                     + ", which the securityProviders leg does not list")
            ptype = str(provider.get("type") or "").strip().lower()
            if not ptype:
                return not_evaluated("security provider " + str(pid) + " has no type")
            admins.append({"name": name, "local": ptype == "local",
                           "source": ptype + " provider " + str(provider.get("name") or pid)})
        summary = {"users": len(users), "securityProviders": len(providers)}
        if not admins:
            return not_evaluated("no enabled user with the Administrator permission (perm_admin) was "
                                 "returned, so the administrator population was not read", summary)
        return judge(admins, summary)
    except Exception as error:
        return create_response(result={CRITERIA_KEY: None}, transformation_errors=[str(error)],
                               api_errors=["transformation error: " + str(error)[:200]],
                               fail_reasons=["Not evaluated: " + str(error)[:200]])
