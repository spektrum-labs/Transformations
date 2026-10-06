"""
Transformation: areBackupConsoleAdminsDedicated
Vendor: Veeam  |  Category: Backup  |  Product: Veeam Service Provider Console (REST API v3)
Claim (IAM-004): the backup console is administered only by dedicated admin accounts, never a person's
everyday SSO identity.
API Source: workflow getConsoleAdmins, two read-only calls merged under output keys:
    users          GET /api/v3/users                                   (portal users: userName, role, status, profile.email)
    localUserRules GET /api/v3/users/serviceProvider/localUserRule     (Windows accounts and groups given portal roles:
                                                                        name, type winNTUser | winNTGroup, contextType
                                                                        machine | domain | applicationDirectory,
                                                                        roleType, enabled)
    Each is a VSPC v3 collection {"meta": {"pagingInfo": {"total", "count", "offset"}}, "data": [...], "errors": null}.
    Schema: VSPC REST API v3 OpenAPI (User, LocalUserRule, WinContextType, LocalUserRuleRoleType).
Rule: administrators are enabled portal users with an administrator or owner role (PortalAdministrator,
SiteAdministrator, ResellerOwner, ResellerAdministrator, CompanyOwner, CompanyAdministrator,
CompanyLocationAdministrator) and enabled local-user rules with roleType portalAdministrator or
siteAdministrator. A Windows user local to the VSPC server (contextType machine) is a console account
(dedicated). A domain user is dedicated only when its name marks it as an admin account; a Windows group only
when its name marks it as an admin group. VSPC does not say whether a portal user signs in with a VSPC password
or through an identity provider, so an unmarked portal administrator cannot be classified (not evaluated).
True: every administrator is dedicated. False: any administrator is an everyday domain account or group.
None (not evaluated): empty, error or partial input, unclassifiable administrators, or none in the read.
"""
import json
import re
from datetime import datetime, timezone

KEY = "areBackupConsoleAdminsDedicated"

#: The criterion this file answers. None means "not measured", never "failed".
NONE_MEANS_NOT_EVALUATED = (KEY,)

WRAPPERS = ("apiResponse", "api_response", "response", "result", "Output", "_response_data")

#: Words that name an account as an administrative identity (adm-jsmith, jsmith.admin, t0-jsmith,
#: BUILTIN\Administrators, Backup-Admins). Matched as whole words of the account name; "admin" is also
#: matched as a prefix or suffix of a word (adminjsmith, veeamadmin).
ADMIN_WORDS = ("adm", "admin", "admins", "administrator", "administrators", "priv", "privileged",
               "pam", "breakglass", "emergency", "sysadmin", "sysadmins", "superuser", "root",
               "tier0", "tier1", "t0", "t1")

#: Words that name a user as a non-person service or console account (svc-backup, veeam.service).
#: Accepted for users only: a group named after the product ("Veeam Users") is not an admin group.
SERVICE_WORDS = ("svc", "service", "services", "serviceaccount", "backup", "backups", "bkp",
                 "veeam", "rubrik", "cohesity", "commvault", "helios", "vspc", "vbr", "rsc")

#: Short tier prefixes or suffixes (a-jsmith, jsmith_a, pa-jsmith). Only with a hyphen or an underscore,
#: never a dot, so a surname plus initial (smith.a) is not read as an admin account.
SHORT_AFFIXES = ("a", "pa", "da", "ea", "sa", "x")

MAX_LISTED = 25


def to_obj(raw):
    """A parsed JSON value, or None for an empty or unparseable body."""
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    if isinstance(raw, str):
        text = raw.strip()
        if text == "":
            return None
        try:
            return json.loads(text)
        except Exception:
            return None
    return raw


def unwrap(raw):
    """(body, validation) with the Token-Service envelope and Integration-Service wrappers removed."""
    validation = {"status": "unknown", "errors": [], "warnings": ["Legacy input format - no schema validation performed"]}
    cur = to_obj(raw)
    if isinstance(cur, dict) and "validation" in cur and "data" in cur:
        if isinstance(cur.get("validation"), dict):
            validation = cur.get("validation")
        cur = to_obj(cur.get("data"))
    for depth in range(8):
        if not isinstance(cur, dict):
            break
        nxt = None
        for w in WRAPPERS:
            if isinstance(cur.get(w), (dict, str)):
                nxt = to_obj(cur.get(w))
                break
        if nxt is None:
            break
        cur = nxt
    return cur, validation


def envelope_error(obj):
    """A short reason when obj is an error envelope rather than a vendor body, else None."""
    if not isinstance(obj, dict):
        return None
    err = obj.get("error")
    if err is True or isinstance(err, (str, dict)):
        detail = obj.get("message") or err
        if isinstance(detail, dict):
            detail = detail.get("message") or json.dumps(detail)[:200]
        return "the call did not return data: " + str(detail)[:300]
    code = obj.get("statusCode")
    if code is None:
        code = obj.get("status_code")
    if code is None and isinstance(obj.get("status"), int):
        code = obj.get("status")
    if isinstance(code, int) and not isinstance(code, bool) and code >= 400:
        return "the call returned HTTP " + str(code)
    if obj.get("status") == "Error":
        return "the call did not return data: " + str(obj.get("message") or "error")[:300]
    return None


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None,
                    transformation_errors=None, api_errors=None, additional_findings=None):
    """Standardized transformation response (CONTRIBUTING.md)."""
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    transform_err_list = transformation_errors or []
    response_metadata = {
        "evaluatedAt": datetime.now(timezone.utc).isoformat(),
        "schemaVersion": "2.0",
        "transformationId": KEY,
        "vendor": VENDOR,
        "product": PRODUCT,
        "category": "Backup",
    }
    if metadata:
        response_metadata.update(metadata)
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if api_err_list else "success", "errors": api_err_list},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": "error" if transform_err_list else "success",
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


def not_measured(validation, reason, recommendation=None, summary=None):
    """None with dataCollection status "error", so Token-Service records Not evaluated, not Failed."""
    return create_response(
        result={KEY: None},
        validation=validation,
        fail_reasons=[reason],
        recommendations=[recommendation] if recommendation else [],
        input_summary=summary or {},
        api_errors=[reason],
    )


def split_identity(name):
    """(account, domain) from DOMAIN\\account, account@domain or a bare account name, lower-cased."""
    text = str(name or "").strip().lower()
    domain = ""
    if "\\" in text:
        parts = text.split("\\")
        domain = parts[0]
        text = parts[-1]
    if "@" in text:
        parts = text.split("@")
        text = parts[0]
        domain = parts[-1]
    return text, domain


def word_is_admin(word):
    if word in ADMIN_WORDS:
        return True
    return word.startswith("admin") or word.endswith("admin") or word.endswith("admins")


def has_admin_marker(name, allow_service):
    """True when the name itself marks the account as an administrative (or, for users, service) identity."""
    account, domain = split_identity(name)
    if account == "":
        return False
    words = [w for w in re.split(r"[^a-z0-9]+", account) if w]
    for w in words:
        if word_is_admin(w):
            return True
        if allow_service and w in SERVICE_WORDS:
            return True
    for a in SHORT_AFFIXES:
        if account.startswith(a + "-") or account.startswith(a + "_"):
            return True
        if account.endswith("-" + a) or account.endswith("_" + a):
            return True
    label = domain.split(".")[0] if domain else ""
    if label:
        label_words = [w for w in re.split(r"[^a-z0-9]+", label) if w]
        for w in label_words:
            if word_is_admin(w) or w.endswith("adm") or w.startswith("priv") or w in ("t0", "tier0"):
                return True
    return False


def classify(names, principal, identity):
    """How one console administrator is held.

    principal: "user" or "group". identity: "local" (an account that exists only in the console),
    "service" (a non-person API or service account), "directory" (a directory account such as
    DOMAIN\\user), "sso" (an identity-provider identity) or "unknown" (the API does not say).
    Returns one of: local, service, named (a directory or SSO identity named as an admin account),
    group (a group named as an admin group), everyday, everyday-group, unclassified.
    """
    marked_admin = False
    marked_service = False
    for n in names:
        if n and has_admin_marker(n, False):
            marked_admin = True
        if n and has_admin_marker(n, True):
            marked_service = True
    if principal == "group":
        return "group" if marked_admin else "everyday-group"
    if identity == "local":
        return "local"
    if identity == "service":
        return "service"
    if marked_service:
        return "named"
    if identity in ("directory", "sso"):
        return "everyday"
    return "unclassified"


def first_name(names):
    for n in names:
        if n:
            return str(n)
    return "(unnamed)"


def verdict(validation, admins, role_label, summary_extra=None):
    """The criterion from the console administrators found in a complete read.

    admins: list of {"name", "class", "role"}. False when any administrator is an everyday identity or
    an everyday group; None when none was found or any could not be classified; True only when every
    administrator is a local console account, a service account, an admin-named identity or an
    admin-named group.
    """
    counts = {}
    for c in ("local", "service", "named", "group", "everyday", "everyday-group", "unclassified"):
        counts[c] = 0
    for a in admins:
        counts[a["class"]] = counts.get(a["class"], 0) + 1
    everyday = [a["name"] for a in admins if a["class"] in ("everyday", "everyday-group")]
    unclassified = [a["name"] for a in admins if a["class"] == "unclassified"]
    summary = {
        "consoleAdministrators": len(admins),
        "localConsoleAccounts": counts["local"],
        "serviceAccounts": counts["service"],
        "adminNamedIdentities": counts["named"],
        "adminNamedGroups": counts["group"],
        "everydayIdentities": counts["everyday"],
        "everydayGroups": counts["everyday-group"],
        "unclassified": counts["unclassified"],
        "everydayAdministrators": everyday[:MAX_LISTED],
        "unclassifiedAdministrators": unclassified[:MAX_LISTED],
    }
    if summary_extra:
        summary.update(summary_extra)
    if len(admins) == 0:
        return not_measured(validation,
                            "The read listed no account or group holding " + role_label + ". Every console has at least "
                            "one administrator, so the administrators were not in what was read; the control's state is unknown.",
                            "Give the integration account read access to the console's users and roles.", summary)
    if len(everyday) > 0:
        return create_response(
            result={KEY: False},
            validation=validation,
            fail_reasons=[str(len(everyday)) + " of " + str(len(admins)) + " console administrators hold " + role_label +
                          " on an everyday identity (a directory or SSO account, or a group, not named as a dedicated "
                          "admin account): " + ", ".join(everyday[:10]) + ("" if len(everyday) <= 10 else ", ...")],
            recommendations=["Grant " + role_label + " only to dedicated admin accounts: a local console account, a "
                             "service account, or a separate directory or SSO identity named as an admin account "
                             "(for example adm-<name>), or a dedicated admin group. Remove it from everyday identities "
                             "and general-purpose groups."],
            input_summary=summary,
        )
    if len(unclassified) > 0:
        return not_measured(validation,
                            str(len(unclassified)) + " of " + str(len(admins)) + " console administrators could not be "
                            "classified: the API does not say whether they sign in with a console account or an SSO "
                            "identity, and the name does not mark them as admin accounts (" +
                            ", ".join(unclassified[:10]) + "). Dedicated versus everyday cannot be shown.",
                            "Name dedicated admin accounts distinctly (for example adm-<name>), or provide the console's "
                            "user list showing how each administrator signs in.", summary)
    return create_response(
        result={KEY: True},
        validation=validation,
        pass_reasons=["All " + str(len(admins)) + " holders of " + role_label + " are dedicated admin accounts: " +
                      str(counts["local"]) + " local console account(s), " + str(counts["service"]) +
                      " service account(s), " + str(counts["named"]) + " directory or SSO identity(ies) named as admin "
                      "accounts and " + str(counts["group"]) + " admin-named group(s)."],
        input_summary=summary,
    )


METHOD = "getConsoleAdmins"
VENDOR = "Veeam"
PRODUCT = "Veeam Service Provider Console (REST API v3)"
ROLE_LABEL = "a VSPC administrator or owner role"

PORTAL_ADMIN_ROLES = ("portaladministrator", "siteadministrator", "reselleradministrator", "resellerowner",
                      "companyowner", "companyadministrator", "companylocationadministrator")
RULE_ADMIN_ROLES = ("portaladministrator", "siteadministrator")


def collection_error(obj):
    if not isinstance(obj, dict):
        return None
    errs = obj.get("errors")
    if isinstance(errs, list) and len(errs) > 0:
        first = errs[0] if isinstance(errs[0], dict) else {}
        return "VSPC returned an error: " + str(first.get("message") or first.get("type") or errs[0])[:300]
    return envelope_error(obj)


def workflow_part(body, key):
    """The named part of the merged workflow body, or None."""
    cur = body
    for depth in range(6):
        if not isinstance(cur, dict):
            return None
        if key in cur:
            return to_obj(cur.get(key))
        nxt = None
        for w in WRAPPERS + ("data",):
            if isinstance(cur.get(w), (dict, str)):
                nxt = to_obj(cur.get(w))
                break
        if nxt is None:
            return None
        cur = nxt
    return None


def complete_items(part, what):
    """(items, None) for a complete VSPC collection read, else (None, reason)."""
    cur = part
    for depth in range(4):
        if cur is None:
            return None, what + ": the part is missing or empty"
        if not isinstance(cur, dict):
            return None, what + ": the part is not a JSON object"
        why = collection_error(cur)
        if why:
            return None, what + ": " + why
        if isinstance(cur.get("data"), list) and isinstance(cur.get("meta"), dict):
            break
        nxt = None
        for w in WRAPPERS:
            if isinstance(cur.get(w), (dict, str)):
                nxt = to_obj(cur.get(w))
                break
        if nxt is None:
            return None, what + ": no VSPC collection (meta + data array)"
        cur = nxt
    if not (isinstance(cur, dict) and isinstance(cur.get("data"), list) and isinstance(cur.get("meta"), dict)):
        return None, what + ": no VSPC collection (meta + data array)"
    items = cur.get("data")
    paging = cur.get("meta").get("pagingInfo")
    total = paging.get("total") if isinstance(paging, dict) else None
    if isinstance(total, bool) or not isinstance(total, int):
        return None, what + ": no meta.pagingInfo.total, so a complete read cannot be shown"
    if len(items) < total:
        return None, what + ": read " + str(len(items)) + " of " + str(total) + "; the remaining pages were not read"
    for it in items:
        if not isinstance(it, dict):
            return None, what + ": an entry is not an object"
    return items, None


def transform(input):
    # Reading input.get("data") marks this transform as new-format for Token-Service, which then hands it the
    # undrilled response as {"data": <response>, "validation": ...}. Without it Token-Service drills through
    # "data" and the completeness proof (pagination, pageInfo, totals) is lost.
    validation = {"status": "unknown", "errors": [], "warnings": []}
    try:
        if isinstance(input, dict) and "validation" in input and "data" in input:
            if isinstance(input.get("validation"), dict):
                validation = input.get("validation")
            body = unwrap(input.get("data"))[0]
        else:
            body, validation = unwrap(input)
        if body is None:
            return not_measured(validation, "The response body is empty; nothing was read from the Service Provider Console.")
        why = collection_error(body)
        if why:
            return not_measured(validation, "Veeam Service Provider Console: " + why + ". This is a credential or "
                                "role result, not a finding.",
                                "The users and local-user-rule endpoints need a Portal Administrator integration account.")
        users, why = complete_items(workflow_part(body, "users"), "users")
        if why:
            return not_measured(validation, "Veeam Service Provider Console " + why + ".")
        rules, why = complete_items(workflow_part(body, "localUserRules"), "localUserRules")
        if why:
            return not_measured(validation, "Veeam Service Provider Console " + why + ".")
        admins = []
        for u in users:
            if str(u.get("status") or "Enabled").lower() != "enabled":
                continue
            if str(u.get("role") or "").lower() not in PORTAL_ADMIN_ROLES:
                continue
            profile = u.get("profile") if isinstance(u.get("profile"), dict) else {}
            names = [u.get("userName"), profile.get("email")]
            admins.append({"name": first_name(names), "class": classify(names, "user", "unknown")})
        for r in rules:
            if r.get("enabled") is False:
                continue
            if str(r.get("roleType") or "").lower() not in RULE_ADMIN_ROLES:
                continue
            context = str(r.get("contextType") or "").lower()
            rtype = str(r.get("type") or "").lower()
            principal = "group" if rtype == "winntgroup" else "user"
            if rtype not in ("winntgroup", "winntuser"):
                identity = "unknown"
            elif context == "machine":
                identity = "local"
            elif context in ("domain", "applicationdirectory"):
                identity = "directory"
            else:
                identity = "unknown"
            names = [r.get("name")]
            admins.append({"name": first_name(names), "class": classify(names, principal, identity)})
        return verdict(validation, admins, ROLE_LABEL, {"portalUsersRead": len(users), "localUserRulesRead": len(rules)})
    except Exception as e:
        return not_measured(validation, "Transformation error: " + str(e)[:300])
