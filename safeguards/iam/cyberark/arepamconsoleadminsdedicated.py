"""
Transformation: arePAMConsoleAdminsDedicated
Vendor: CyberArk Privilege Cloud / PAM Self-Hosted (PVWA)  |  Category: Identity and Access Management

CLAIM. The privileged access management console is administered only by dedicated admin
accounts, not by people's everyday SSO identities.

SOURCE. PVWA Users API with extended details (a NEW method; the CyberArk integration does
not read it today -- see the Integration-Service plan):
  GET {pvwaUrl}/PasswordVault/API/Users?ExtendedDetails=true   (vault permission: Audit users)
  -> {"Users": [User], "Total": n}
  User: id, username, source ("CyberArk" = a Vault user, "LDAP" = a directory-mapped user),
        userType (e.g. "Built-InAdmins", "EPVUser"), componentUser, suspended, enableUser,
        vaultAuthorization [...], groupsMembership [{groupID, groupName, groupType}],
        allowedAuthenticationMethods / authenticationMethod [...]
  CyberArk PAS REST API reference, Users > Get users (docs.cyberark.com, PAM Self-Hosted and
  Privilege Cloud); response example with groupsMembership "Vault Admins": BlinkOps CyberArk
  list-users action (docs.blinkops.com/docs/integrations/cyberark/actions/list-users).

RULE. Console administrators are the enabled, non-component users that are any of: userType
"Built-InAdmins"; a member of the "Vault Admins" group; or holders of a vault authorization
that administers the Vault (AddUpdateUsers, ActivateUsers, ResetUsersPasswords,
ManageDirectoryMapping, AddNetworkAreas, ManageServerFileCategories, BackupAllSafes,
RestoreAllSafes, AddSafes). "AuditUsers" alone is read-only and is not admin. Each must be a
dedicated admin account, which is either
  (a) LOCAL: source "CyberArk" and no allowed authentication method that hands sign-in to the
      directory or IdP (SAML, OIDC, LDAP, Windows/Kerberos), so only Vault-held credentials
      (password, PKI, RADIUS) open it, or
  (b) SEPARATELY NAMED: its username's first or last token is an admin marker (adm, admin,
      administrator, priv, tier0, t0), e.g. adm-jdoe -- a distinct identity kept for admin work.
True when every administrator is (a) or (b). False when any administrator is directory-mapped
or SSO-signed under an ordinary personal username: the person's everyday identity holding
Vault admin.

FAIL CLOSED (None, dataCollection "error", never a pass): an empty or error body; no Users
list; Total above the rows returned (partial); no user carrying vaultAuthorization or
groupsMembership (the read was not made with ExtendedDetails=true, so admin rights are
unknown); no administrator found.
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
VENDOR = "CyberArk"
ADMIN_AUTHORIZATIONS = ("AddUpdateUsers", "ActivateUsers", "ResetUsersPasswords", "ManageDirectoryMapping",
                        "AddNetworkAreas", "ManageServerFileCategories", "BackupAllSafes",
                        "RestoreAllSafes", "AddSafes")
FEDERATED_METHODS = ("saml", "authtypesaml", "oidc", "authtypeoidc", "ldap", "authtypeldap",
                     "windows", "authtypewindows", "kerberos", "authtypekerberos")


def auth_methods(user):
    methods = []
    for key in ("allowedAuthenticationMethods", "authenticationMethod"):
        value = user.get(key)
        if isinstance(value, list):
            methods.extend([str(m).strip().lower() for m in value])
        elif isinstance(value, str) and value.strip():
            methods.append(value.strip().lower())
    return methods


def transform(input):
    try:
        data = unwrap(parse(input))
        if data is None or data == {} or data == []:
            return not_evaluated("empty response: no CyberArk users were read")
        reason = error_reason(data)
        if reason:
            return not_evaluated(reason)
        if isinstance(data, dict) and data.get("ErrorCode"):
            return not_evaluated("CyberArk error " + str(data.get("ErrorCode")))
        if not isinstance(data, dict) or not isinstance(data.get("Users"), list):
            return not_evaluated("no Users list in the response")
        users = data["Users"]
        total = data.get("Total")
        if isinstance(total, int) and total > len(users):
            return not_evaluated("only " + str(len(users)) + " of " + str(total)
                                 + " users were returned: the list is partial")
        extended = [u for u in users if isinstance(u, dict)
                    and ("vaultAuthorization" in u or "groupsMembership" in u)]
        if not extended:
            return not_evaluated("no user carries vaultAuthorization or groupsMembership: the list was "
                                 "not read with ExtendedDetails=true, so admin rights are unknown")
        admins = []
        for u in users:
            if not isinstance(u, dict) or u.get("componentUser") is True:
                continue
            if u.get("suspended") is True or u.get("enableUser") is False:
                continue
            auths = u.get("vaultAuthorization") if isinstance(u.get("vaultAuthorization"), list) else []
            groups = u.get("groupsMembership") if isinstance(u.get("groupsMembership"), list) else []
            group_names = [str(g.get("groupName") or "").strip().lower() for g in groups if isinstance(g, dict)]
            is_admin = (str(u.get("userType") or "") == "Built-InAdmins"
                        or "vault admins" in group_names
                        or len([a for a in auths if a in ADMIN_AUTHORIZATIONS]) > 0)
            if not is_admin:
                continue
            name = str(u.get("username") or u.get("id"))
            source = str(u.get("source") or "").strip()
            methods = auth_methods(u)
            federated = [m for m in methods if m in FEDERATED_METHODS]
            local = source.lower() == "cyberark" and not federated
            if local:
                label = "Vault user"
            elif source.lower() != "cyberark":
                label = (source or "unknown") + " directory mapping"
            else:
                label = "Vault user allowed to sign in by " + "/".join(federated)
            admins.append({"name": name, "local": local, "source": label})
        summary = {"users": len(users), "total": total}
        if not admins:
            return not_evaluated("no Vault administrator was found in the users list, so the "
                                 "administrator population was not read", summary)
        return judge(admins, summary)
    except Exception as error:
        return create_response(result={CRITERIA_KEY: None}, transformation_errors=[str(error)],
                               api_errors=["transformation error: " + str(error)[:200]],
                               fail_reasons=["Not evaluated: " + str(error)[:200]])
