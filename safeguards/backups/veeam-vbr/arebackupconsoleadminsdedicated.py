"""
Transformation: areBackupConsoleAdminsDedicated
Vendor: Veeam  |  Category: Backup  |  Product: Veeam Backup & Replication (REST API v1)
Claim (IAM-004): the backup console is administered only by dedicated admin accounts, never a person's
everyday SSO identity.
API Source: listSecurityUsers (GET {serverUrl}/api/v1/security/users?limit=1000, header x-api-version 1.3-rev1)
    "Get All Users and Groups" (Users and Roles), Veeam Backup & Replication 13 REST API 1.3. Response:
    {"data": [{"id", "name", "type": InternalUser | InternalGroup | ExternalUser | ExternalGroup,
               "roles": [{"id", "name", "description"}], "isServiceAccount"}],
     "pagination": {"total", "count", "skip", "limit"}}
    https://helpcenter.veeam.com/references/vbr/13/rest/1.3-rev1/tag/Users-and-Roles
    The endpoint needs the Veeam Backup Administrator role and VBR 13 (absent from REST 1.2 / VBR 12.3).
Rule: an administrator is a user or group holding a role named "... Administrator" (Veeam Backup
Administrator, Veeam Security Administrator). A service account (isServiceAccount) is dedicated. A user
(Windows, directory or identity-provider) is dedicated only when its name marks it as an admin or service
account (VBR01\\veeamadmin, CORP\\adm-jsmith, a-jsmith@corp.com). A group is a dedicated admin group only
when its name marks it as one (BUILTIN\\Administrators, CORP\\Veeam-Admins); its members are not visible here.
An InternalUser written .\\account is a Windows account local to the VBR server (dedicated).
True: every administrator is dedicated. False: any administrator holds the role through a
general-purpose group. Unevaluated: a directory or SSO identity whose name carries no admin marker.
None (not evaluated): empty, error or partial input, or no administrator in the read.
Limits: the users response does not carry the VBR server's host name, so a local Windows account written
HOST\\account (VBR01\\veeamop) cannot be told from a domain account (CORP\\jdoe). It is judged by the
name marker like a domain account: VBR01\\veeamadmin passes and an unmarked VBR01\\veeamop reads Not
evaluated, never Failed.
"""
import json
import re
from datetime import datetime, timezone

KEY = "areBackupConsoleAdminsDedicated"

#: The criterion this file answers. None means "not measured", never "failed".
NONE_MEANS_NOT_EVALUATED = (KEY,)

WRAPPERS = ("apiResponse", "api_response", "response", "result", "Output", "_response_data")

#: Words that name an account as an administrative identity (adm-jsmith, jsmith.admin, t0-jsmith,
#: BUILTIN\Administrators, Backup-Admins). Matched only as whole words of the account name (split on every
#: character that is not a letter or digit), never as a prefix or suffix of a longer word, so badmin, padmin
#: and administration are not markers. "pam" and "root" are not here: both are personal names (pam.smith@,
#: joe.root@), so they count only as a joined affix (SHORT_AFFIXES).
ADMIN_WORDS = ("adm", "admin", "admins", "administrator", "administrators", "priv", "privileged",
               "breakglass", "emergency", "sysadmin", "sysadmins", "superuser", "superadmin",
               "tier0", "tier1", "t0", "t1")

#: Product- or function-prefixed admin words, listed one by one (VBR01\veeamadmin, rubrikadmin@). A word that
#: only ends in "admin" is not a marker unless it is listed here.
PREFIXED_ADMIN_WORDS = ("veeamadmin", "veeamadmins", "vbradmin", "vspcadmin", "vspcadmins", "rubrikadmin",
                        "rubrikadmins", "rscadmin", "cohesityadmin", "cohesityadmins", "heliosadmin",
                        "commvaultadmin", "commvaultadmins", "cvadmin", "cvadmins", "backupadmin", "backupadmins",
                        "bkpadmin", "localadmin", "domainadmin", "domainadmins")

#: "admin" written straight onto a name (adminjsmith, admin01) is a common admin-account convention, and no
#: common given name or surname starts with "admin". Such a word counts when any digits or at least three more
#: characters follow "admin". The English words that start with "admin" (administer, administration,
#: administrative, adminicle) all start with "administ" or "adminic", and those do not count.
ADMIN_PREFIX = "admin"
NOT_ADMIN_PREFIXED = ("administ", "adminic")

#: Words that name a user as a non-person service or console account (svc-backup, veeam.service).
#: Accepted for users only: a group named after the product ("Veeam Users") is not an admin group.
SERVICE_WORDS = ("svc", "service", "services", "serviceaccount", "backup", "backups", "bkp",
                 "veeam", "rubrik", "cohesity", "commvault", "helios", "vspc", "vbr", "rsc")

#: Short or ambiguous tier prefixes or suffixes (a-jsmith, jsmith_a, pa-jsmith, pam-jsmith, root_backup). Only
#: when joined to the rest of the account with a hyphen or an underscore, never a dot and never alone, so a
#: surname plus initial (smith.a) and a person named Pam or Root (pam.smith@, pam@, joe.root@) are not read
#: as admin accounts.
SHORT_AFFIXES = ("a", "pa", "da", "ea", "sa", "x", "pam", "root")

#: Whole words of a domain label that name an admin directory or tier (jsmith@admin.corp.example, ADM\jsmith,
#: CORP-ADM\jsmith, jsmith@t0.corp.example). Matched only as whole words, never as a prefix or suffix, so
#: PRIVATECO\, jdoe@cityadm.gov and jdoe@adminsoft.com are not markers.
DOMAIN_ADMIN_WORDS = ("adm", "admin", "admins", "priv", "privileged", "t0", "tier0")

#: Second-level labels under a two-letter country code (example.co.uk, example.com.au). The registrable domain
#: is the organisation's own name and is never read as a marker: jdoe@admin.ch is an everyday address.
SECOND_LEVEL_LABELS = ("co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "go", "gob", "mil", "ltd", "plc")

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
    """True for a whole admin word, a listed product-prefixed admin word, or "admin" written onto a name."""
    if word in ADMIN_WORDS or word in PREFIXED_ADMIN_WORDS:
        return True
    if not word.startswith(ADMIN_PREFIX):
        return False
    for p in NOT_ADMIN_PREFIXED:
        if word.startswith(p):
            return False
    rest = word[len(ADMIN_PREFIX):]
    return rest.isdigit() or len(rest) >= 3


def domain_labels(domain):
    """The domain labels that may name an admin directory: a NetBIOS name (CORP-ADM) as it is, or the
    subdomain labels of a DNS name (admin in admin.corp.example). Never the registrable domain itself."""
    labels = [x for x in domain.split(".") if x]
    if len(labels) <= 1:
        return labels
    keep = 2
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in SECOND_LEVEL_LABELS:
        keep = 3
    return labels[:-keep]


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
    for label in domain_labels(domain):
        for w in re.split(r"[^a-z0-9]+", label):
            if w in DOMAIN_ADMIN_WORDS:
                return True
    return False


def classify(names, principal, identity):
    """How one console administrator is held.

    principal: "user" or "group". identity: "local" (an account that exists only in the console),
    "service" (a non-person API or service account), "directory" (a directory account such as
    DOMAIN\\user), "sso" (an identity-provider identity) or "unknown" (the API does not say).
    Returns one of: local, service, named (a directory or SSO identity named as an admin account),
    group (a group named as an admin group), unmarked (a directory or SSO identity with no admin
    marker: dedicated versus everyday cannot be told from the name), everyday-group, unclassified.
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
        return "unmarked"
    return "unclassified"


def first_name(names):
    for n in names:
        if n:
            return str(n)
    return "(unnamed)"


def verdict(validation, admins, role_label, summary_extra=None):
    """The criterion from the console administrators found in a complete read.

    admins: list of {"name", "class", "role"}. False when any administrator is an everyday group; None
    when none was found, any directory or SSO identity carries no admin marker, or any could not be
    classified; True only when every
    administrator is a local console account, a service account, an admin-named identity or an
    admin-named group.
    """
    counts = {}
    for c in ("local", "service", "named", "group", "unmarked", "everyday-group", "unclassified"):
        counts[c] = 0
    for a in admins:
        counts[a["class"]] = counts.get(a["class"], 0) + 1
    everyday = [a["name"] for a in admins if a["class"] == "everyday-group"]
    unmarked = [a["name"] for a in admins if a["class"] == "unmarked"]
    unclassified = [a["name"] for a in admins if a["class"] == "unclassified"]
    summary = {
        "consoleAdministrators": len(admins),
        "localConsoleAccounts": counts["local"],
        "serviceAccounts": counts["service"],
        "adminNamedIdentities": counts["named"],
        "adminNamedGroups": counts["group"],
        "unmarkedIdentities": counts["unmarked"],
        "everydayGroups": counts["everyday-group"],
        "unclassified": counts["unclassified"],
        "everydayAdministrators": everyday[:MAX_LISTED],
        "unmarkedAdministrators": unmarked[:MAX_LISTED],
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
                          " through a general-purpose group (a group not named as a dedicated admin group): " + ", ".join(everyday[:10]) + ("" if len(everyday) <= 10 else ", ...")],
            recommendations=["Grant " + role_label + " only to dedicated admin accounts: a local console account, a "
                             "service account, or a separate directory or SSO identity named as an admin account "
                             "(for example adm-<name>), or a dedicated admin group. Remove it from everyday identities "
                             "and general-purpose groups."],
            input_summary=summary,
        )
    if len(unmarked) > 0:
        return not_measured(validation,
                            str(len(unmarked)) + " of " + str(len(admins)) + " console administrators are directory or "
                            "SSO identities whose names carry no admin marker (" + ", ".join(unmarked[:10]) +
                            "). A dedicated admin identity and an everyday one look the same here, so dedicated versus "
                            "everyday cannot be shown.",
                            "Name dedicated admin identities distinctly (for example adm-<name>), or provide the "
                            "identity provider's record showing these are separate admin accounts.", summary)
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


METHOD = "listSecurityUsers"
VENDOR = "Veeam"
PRODUCT = "Veeam Backup & Replication"
ROLE_LABEL = "a Veeam Backup & Replication administrator role"

TYPE_IDENTITY = {"internaluser": ("user", "directory"), "externaluser": ("user", "sso"),
                 "internalgroup": ("group", "directory"), "externalgroup": ("group", "sso")}


def find_collection(body):
    """(items, None) for a complete VBR collection read, else (None, reason).
    A VBR v1 collection is {"data": [...], "pagination": {"total", "count", "skip", "limit"}}."""
    cur = body
    for depth in range(4):
        if not isinstance(cur, dict):
            return None, "the response is not a JSON object"
        if isinstance(cur.get("data"), list) and isinstance(cur.get("pagination"), dict):
            break
        nxt = to_obj(cur.get("data")) if isinstance(cur.get("data"), (dict, str)) else None
        if nxt is None:
            return None, "no users collection (data + pagination) in the response"
        cur = nxt
    if not (isinstance(cur, dict) and isinstance(cur.get("data"), list) and isinstance(cur.get("pagination"), dict)):
        return None, "no users collection (data + pagination) in the response"
    items = cur.get("data")
    total = cur.get("pagination").get("total")
    if isinstance(total, bool) or not isinstance(total, int):
        return None, "no pagination.total, so a complete read cannot be shown"
    if len(items) < total:
        return None, "read " + str(len(items)) + " of " + str(total) + " users and groups; the rest were not read"
    for it in items:
        if not isinstance(it, dict):
            return None, "a user entry is not an object"
    return items, None


def admin_roles(item):
    """Names of administrator roles the entry holds, or None when it carries no roles list."""
    roles = item.get("roles")
    if not isinstance(roles, list):
        return None
    out = []
    for r in roles:
        name = r.get("name") if isinstance(r, dict) else r
        if "administrator" in str(name or "").lower():
            out.append(str(name))
    return out


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
            return not_measured(validation, "The response body is empty; nothing was read from Veeam Backup & Replication.")
        why = envelope_error(body)
        if why is None and isinstance(body, dict) and isinstance(body.get("errorCode"), str):
            why = "the call returned " + str(body.get("errorCode")) + ": " + str(body.get("message") or "")[:200]
        if why:
            return not_measured(validation, "Veeam Backup & Replication: " + why + ". This is a credential, role or "
                                "version result, not a finding.",
                                "The users endpoint needs Veeam Backup & Replication 13 and an integration account with "
                                "the Veeam Backup Administrator role.")
        items, why = find_collection(body)
        if why:
            return not_measured(validation, "Veeam Backup & Replication: " + why + ".")
        admins = []
        for it in items:
            roles = admin_roles(it)
            if roles is None:
                return not_measured(validation, "A user entry carries no roles list, so who administers the console "
                                    "cannot be read.")
            if len(roles) == 0:
                continue
            shape = TYPE_IDENTITY.get(str(it.get("type") or "").lower(), ("user", "unknown"))
            identity = shape[1]
            if shape == ("user", "directory") and str(it.get("name") or "").startswith(".\\"):
                identity = "local"
            if shape[0] == "user" and it.get("isServiceAccount") is True:
                identity = "service"
            names = [it.get("name")]
            admins.append({"name": first_name(names), "class": classify(names, shape[0], identity)})
        return verdict(validation, admins, ROLE_LABEL, {"usersAndGroupsRead": len(items)})
    except Exception as e:
        return not_measured(validation, "Transformation error: " + str(e)[:300])
