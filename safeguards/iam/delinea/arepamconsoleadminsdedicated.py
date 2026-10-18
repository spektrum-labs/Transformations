"""
Transformation: arePAMConsoleAdminsDedicated
Vendor: Delinea Secret Server (Secret Server Cloud and on-premises)  |  Category: Identity and Access Management

CLAIM. The privileged access management console is administered only by dedicated admin
accounts, not by people's everyday SSO identities.

SOURCE. Workflow getConsoleAdmins (NEW; see the Integration-Service plan), the same
merge-then-iterate shape as getSecretPolicies:
  searchUsers           GET {secretServerUrl}/api/v1/users?take=1000&filter.includeInactive=false
                        -> {"records": [UserSummary], "total", "hasNext", ...}   (merged)
  getUserRolesAssigned  GET {secretServerUrl}/api/v1/users/{userId}/roles-assigned, iterated over
                        records (userId <- id), output key userRoles: one body per user, same
                        order -> {"records": [{"roleId", "roleName", "isDirectAssignment", "groups"}]}
  UserSummary: id, userName, displayName, domainId (-1 = local Secret Server user, else an AD
  domain), domainName, enabled, isApplicationAccount, externalUserSource ("None",
  "ThycoticOne" = Delinea Platform, "Azure"), platformIntegrationType.
  Secret Server REST API reference (Users: Search Users, Get User Roles Assigned); field names
  as modelled by Delinea's thycotic.secretserver PowerShell module (UserSummary,
  UserRoleSummary, UserSourceType).

RULE. Console administrators are enabled, non-application users holding at least one role
whose name contains "admin" (the built-in "Administrator" role and custom admin roles). Each
must be a dedicated admin account, which is either
  (a) LOCAL: domainId -1, externalUserSource "None" or empty, and no platformIntegrationType
      -- a Secret Server account, not an AD-synced, Delinea Platform or Entra identity, or
  (b) SEPARATELY NAMED: its userName's first or last token is an admin marker (adm, admin,
      administrator, priv, tier0, t0), e.g. adm-jdoe or DOMAIN\\jdoe-admin.
True when every administrator is (a) or (b). False when any administrator is a directory,
Platform or Entra identity under an ordinary personal name: the person's everyday SSO
identity holding Secret Server admin.

USER-TO-ROLES MATCH. Each userRoles entry is matched to a user by list position
(userRoles[i] belongs to records[i]), because the roles-assigned body carries no user id. When
an entry does carry one -- the entry shape {"userId", "roles": <roles body>}, or a userId on
the body or on its role records -- it must equal that user's id, or the user is not evaluated.
Until the Integration-Service workflow emits the keyed shape, a fan-out that returned legs out
of order would attribute roles to the wrong user and could not be detected here.

LIMITS. Stated so a reviewer can see them, not hidden.
  * Admin is read from role names, not role permissions; a custom role that grants Administer
    permissions under a name without "admin" is not counted.
  * Positional user-to-roles matching, as above, when no user id is present.
  * Roles granted through groups are counted only if roles-assigned returns them. Its
    UserRoleSummary carries isDirectAssignment and groups, which indicates group-inherited
    roles are included, but this has not been confirmed against a live tenant.

FAIL CLOSED (None, dataCollection "error", never a pass): an empty or error body; no records
list; hasNext true or total above the rows returned (partial); a userRoles list missing or of
a different length from records, or any per-user roles body that is an error or has no
records list (roles unread for that user); a per-user roles body with hasNext true or total
above the role records returned (roles partly read for that user); a roles entry whose user id
does not match the user at that position; no administrator found; an administrator with no
domainId.
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


def roles_entry(entry, user):
    """(roles body, problem) for one userRoles entry. Accepts the plain roles-assigned body or
    the keyed shape {"userId", "roles": body}; checks any user id the entry carries."""
    body = entry
    ids = []
    if isinstance(entry, dict) and isinstance(entry.get("roles"), (dict, list)) and not isinstance(
            entry.get("records"), list):
        for key in ("userId", "user_id", "id"):
            if entry.get(key) is not None:
                ids.append(entry.get(key))
        body = entry["roles"]
        if isinstance(body, list):
            body = {"records": body}
    if isinstance(body, dict) and not isinstance(body.get("records"), list):
        body = unwrap(body)
    if isinstance(body, dict):
        for key in ("userId", "user_id"):
            if body.get(key) is not None:
                ids.append(body.get(key))
        if isinstance(body.get("records"), list):
            for r in body["records"]:
                if isinstance(r, dict) and r.get("userId") is not None:
                    ids.append(r.get("userId"))
    user_id = user.get("id")
    for found in ids:
        if user_id is None or str(found) != str(user_id):
            return body, ("its roles entry is for user id " + str(found)[:40] + ", not "
                          + str(user_id)[:40] + ": roles and users are out of step")
    return body, None


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
VENDOR = "Delinea Secret Server"


def transform(input):
    try:
        data = unwrap(parse(input))
        if data is None or data == {} or data == []:
            return not_evaluated("empty response: no Secret Server users were read")
        reason = error_reason(data)
        if reason:
            return not_evaluated(reason)
        if not isinstance(data, dict) or not isinstance(data.get("records"), list):
            return not_evaluated("no users list (records) in the response")
        users = data["records"]
        total = data.get("total")
        if data.get("hasNext") is True or (isinstance(total, int) and total > len(users)):
            return not_evaluated("only " + str(len(users)) + " of " + str(total)
                                 + " users were returned: the list is partial")
        roles_by_user = data.get("userRoles")
        if not isinstance(roles_by_user, list) or len(roles_by_user) != len(users):
            return not_evaluated("userRoles is missing or does not hold one roles body per user, so "
                                 "who holds an admin role is unknown")
        admins = []
        for index in range(len(users)):
            u = users[index]
            if not isinstance(u, dict):
                continue
            if u.get("enabled") is False or u.get("isApplicationAccount") is True:
                continue
            name = str(u.get("userName") or u.get("displayName") or u.get("id"))
            body, mismatch = roles_entry(roles_by_user[index], u)
            if mismatch:
                return not_evaluated("roles for user " + name + " were not matched: " + mismatch)
            body_error = error_reason(body)
            if body_error or not isinstance(body, dict) or not isinstance(body.get("records"), list):
                return not_evaluated("roles for user " + name + " were not read"
                                     + (": " + body_error if body_error else ""))
            role_total = body.get("total")
            if body.get("hasNext") is True or (isinstance(role_total, int)
                                               and role_total > len(body["records"])):
                return not_evaluated("roles for user " + name + " were only partly read ("
                                     + str(len(body["records"])) + " of " + str(role_total) + ")")
            role_names = [str(r.get("roleName") or r.get("name") or "") for r in body["records"]
                          if isinstance(r, dict)]
            admin_roles = [r for r in role_names if "admin" in r.lower()]
            if not admin_roles:
                continue
            domain_id = u.get("domainId")
            if domain_id is None:
                return not_evaluated("administrator " + name + " has no domainId")
            source = str(u.get("externalUserSource") or "").strip()
            platform = str(u.get("platformIntegrationType") or "").strip()
            local = (str(domain_id) == "-1" and source.lower() in ("", "none")
                     and platform.lower() in ("", "none"))
            if local:
                label = "local Secret Server account"
            elif str(domain_id) != "-1":
                label = "directory domain " + str(u.get("domainName") or domain_id)
            else:
                label = (source if source.lower() not in ("", "none") else platform) + " identity"
            admins.append({"name": name, "local": local, "source": label})
        summary = {"users": len(users), "total": total}
        if not admins:
            return not_evaluated("no enabled user holds a Secret Server admin role, so the "
                                 "administrator population was not read", summary)
        return judge(admins, summary)
    except Exception as error:
        return create_response(result={CRITERIA_KEY: None}, transformation_errors=[str(error)],
                               api_errors=["transformation error: " + str(error)[:200]],
                               fail_reasons=["Not evaluated: " + str(error)[:200]])
