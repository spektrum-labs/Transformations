"""
Transformation: areBackupConsoleAdminsDedicated
Vendor: Commvault  |  Category: Backup  |  Product: Commvault Command Center / CommServe (REST API V4)
Claim (IAM-004): the backup console is administered only by dedicated admin accounts, never a person's
everyday SSO identity.
API Source: workflow getCommCellAdmins, two read-only calls merged under output keys:
    masterGroup  GET {serverUrl}/V4/UserGroup/1                          (the system-created "master" user group:
                                                                          {"id", "name", "enabled", "users": [{"id", "name"}],
                                                                           "associatedExternalGroups": [{"id", "name"}]})
    users        GET {serverUrl}/V4/User?additionalProperties=true       ({"users": [{"id", "name", "email",
                                                                          "userPrincipalName", "enabled"}], "numberOfUsers"})
    Shapes as read by Commvault's own SDK (cvpysdk security/usergroup.py and security/user.py).
Rule: CommCell administrators are the members of the "master" user group: its users and its associated
external (directory) groups. A user named DOMAIN\\user is a directory identity and one named user@domain an
SSO identity; both are dedicated only when the name (or the UPN) marks them as admin accounts. A user with a
bare name is a CommCell-local account (dedicated) only when its record proves it: userType, providerType or
authenticationMethod says local (LOCAL, CommCell), or a domain or provider object is present with id 0 and no
name. A bare name with a userPrincipalName (jdoe + jdoe@corp.example) is an SSO identity. A non-empty domain or
provider, or a non-local type, makes it a directory identity. A null or "" domain is not proof (serializers
emit null for any unset field). With no such signal the sign-in source is unknown: an AD user added by sAMAccountName under a default domain, or a SAML user with a
normalised name, looks the same, so the user is classified by its name marker only and an unmarked one reads
Not evaluated, never True. An external group is dedicated only when its name marks it as an admin
group. The transform checks that group 1 is named "master"; if not, it does not guess.
Not covered: Master-role security associations granted outside the master group.
True: every master member is dedicated. False: any administrator holds the role through a
general-purpose group. Unevaluated: a directory or SSO identity whose name carries no admin marker.
None (not evaluated): empty, error or partial input, group 1 is not "master", or a member's record is missing.
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
SECOND_LEVEL_LABELS = ("co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "go", "gob", "gub", "mil", "ltd",
                       "plc", "gouv", "gv", "gc", "govt", "sch", "nhs", "res", "nic", "int", "gen", "firm", "biz",
                       "info", "nom", "med", "police", "mod", "judiciary", "parliament", "lg", "ed")

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


METHOD = "getCommCellAdmins"
VENDOR = "Commvault"
PRODUCT = "Commvault Command Center (REST API V4)"
ROLE_LABEL = "membership of the CommCell master user group"


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


def part_error(part):
    if not isinstance(part, dict):
        return None
    code = part.get("errorCode")
    if isinstance(code, int) and not isinstance(code, bool) and code != 0:
        return "the call returned errorCode " + str(code) + ": " + str(part.get("errorMessage") or part.get("errorString") or "")[:200]
    return envelope_error(part)


#: Fields of the V4 user record that name the account type or sign-in source.
TYPE_FIELDS = ("userType", "providerType", "authenticationMethod")
SOURCE_FIELDS = ("domain", "domainName", "provider", "providerName", "identityServer")
LOCAL_TYPES = ("local", "localuser", "commcell", "commcelluser")


def field_text(value):
    """A record field as lower-case text with separators removed: a string, or a {"name"} object's name."""
    if isinstance(value, dict):
        value = value.get("name")
    if not isinstance(value, str):
        return ""
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def is_empty_source(value):
    """True only for a domain or provider object with id 0 and no name (Commvault's "no domain")."""
    if isinstance(value, dict) and "id" in value:
        return field_text(value) == "" and value.get("id") in (0, "0")
    return False


def is_set_source(value):
    """True for a domain or provider that names a source: a non-empty string or an object with a name or id."""
    if isinstance(value, str):
        return value.strip() != ""
    if isinstance(value, dict):
        return field_text(value) != "" or value.get("id") not in (None, 0, "", "0")
    return False


def identity_of(user):
    """local, directory, sso or unknown for a CommCell user.

    DOMAIN\\user is directory, and user@domain or a bare name with a userPrincipalName is sso. A bare name is
    local only when the record proves it (a local userType / providerType / authenticationMethod, or a domain
    or provider object with id 0); otherwise it is unknown, never assumed local."""
    name = str(user.get("name") or "")
    if "\\" in name:
        return "directory"
    if "@" in name:
        return "sso"
    upn = user.get("userPrincipalName")
    if isinstance(upn, str) and "@" in upn:
        return "sso"
    for k in TYPE_FIELDS:
        kind = field_text(user.get(k))
        if kind != "":
            return "local" if kind in LOCAL_TYPES else "directory"
    proven_local = False
    for k in SOURCE_FIELDS:
        if is_set_source(user.get(k)):
            return "directory"
        if is_empty_source(user.get(k)):
            proven_local = True
    return "local" if proven_local else "unknown"


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
            return not_measured(validation, "The response body is empty; nothing was read from Commvault.")
        why = part_error(body)
        if why:
            return not_measured(validation, "Commvault: " + why + ". This is a credential or role result, not a finding.",
                                "The integration account needs permission to view users and user groups.")
        group = workflow_part(body, "masterGroup")
        users_part = workflow_part(body, "users")
        if not isinstance(group, dict):
            return not_measured(validation, "Commvault: the master user group was not read.")
        why = part_error(group)
        if why:
            return not_measured(validation, "Commvault master user group: " + why + ".")
        if str(group.get("name") or "").lower() != "master":
            return not_measured(validation, "Commvault: user group 1 is not named master on this CommCell, so the "
                                "CommCell administrators cannot be identified from it.")
        members = group.get("users")
        externals = group.get("associatedExternalGroups")
        if members is None and externals is None:
            return not_measured(validation, "Commvault: the master user group carries no users or external groups "
                                "list, so its membership was not read.")
        members = members if isinstance(members, list) else []
        externals = externals if isinstance(externals, list) else []
        if not isinstance(users_part, dict):
            return not_measured(validation, "Commvault: the user list was not read.")
        why = part_error(users_part)
        if why:
            return not_measured(validation, "Commvault user list: " + why + ".")
        users = users_part.get("users")
        if not isinstance(users, list):
            return not_measured(validation, "Commvault: no users list in the user read.")
        expected = users_part.get("numberOfUsers")
        if isinstance(expected, int) and not isinstance(expected, bool) and len(users) < expected:
            return not_measured(validation, "Commvault: read " + str(len(users)) + " of " + str(expected) +
                                " users; the rest were not read.")
        by_id = {}
        for u in users:
            if isinstance(u, dict) and u.get("id") is not None:
                by_id[str(u.get("id"))] = u
        admins = []
        for m in members:
            if not isinstance(m, dict):
                return not_measured(validation, "Commvault: a master group member entry is not an object.")
            user = by_id.get(str(m.get("id")))
            if user is None:
                return not_measured(validation, "Commvault: master group member " + str(m.get("name") or m.get("id")) +
                                    " is not in the user list, so how it signs in cannot be read.")
            if user.get("enabled") is False:
                continue
            names = [user.get("name") or m.get("name"), user.get("userPrincipalName")]
            admins.append({"name": first_name(names), "class": classify(names, "user", identity_of(user))})
        for g in externals:
            if not isinstance(g, dict):
                return not_measured(validation, "Commvault: an external group entry is not an object.")
            names = [g.get("name")]
            admins.append({"name": first_name(names), "class": classify(names, "group", "directory")})
        return verdict(validation, admins, ROLE_LABEL, {"usersRead": len(users), "masterUsers": len(members),
                                                       "masterExternalGroups": len(externals)})
    except Exception as e:
        return not_measured(validation, "Transformation error: " + str(e)[:300])
