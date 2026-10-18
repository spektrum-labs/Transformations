"""
Transformation: areBackupConsoleAdminsDedicated
Vendor: Rubrik  |  Category: Backup  |  Product: Rubrik Security Cloud (RSC)
Claim (IAM-004): the backup console is administered only by dedicated admin accounts, never a person's
everyday SSO identity.
API Source: listConsoleAdmins (POST https://<account>.my.rubrik.com/api/graphql, read-only query)
    query RscConsoleAdmins($first: Int, $after: String) {
      usersInCurrentAndDescendantOrganization(first: $first, after: $after) {
        count pageInfo { hasNextPage endCursor }
        nodes { id username email domain status isAccountOwner roles { id name isOrgAdmin } } } }
Schema: rubrikinc/rubrik-developer-center docs/Rubrik-Security-Cloud-API/schemas/20260914.graphql
    (type User: domain UserDomainEnum! = LOCAL | SSO | LDAP | CLIENT | PAT | SUPPORT; status UserStatus! =
    ACTIVE | DEACTIVATED | UNKNOWN; roles [Role!]! with isOrgAdmin).
Rule: an administrator is an active user who is the account owner, holds a role with isOrgAdmin, or holds a
role whose name names an admin role in whole words (Administrator, Backup Admins; not Non-Admin Viewer, No
Admin Access or Admin Read Only). LOCAL users are console accounts (dedicated); CLIENT, PAT and SUPPORT users
are non-person accounts (dedicated); SSO and LDAP users are dedicated only when the email or username is named
as an admin account (adm-jsmith@, jsmith.admin@, a-jsmith@, adminjsmith@ ...).
True: every administrator is dedicated.
None (not evaluated): a directory or SSO identity whose name carries no admin marker; empty, error or partial
input; a GraphQL error; or no administrator in the read.
Rubrik never returns False, by design. The shared rule gives False only when an administrator holds the role
through a general-purpose group, and the RSC user list carries users only, never groups. An SSO or LDAP
administrator whose name carries no admin marker reads Not evaluated, not False: J.J.'s ruling of 6 Oct 2026
(an everyday identity and a dedicated one with an unmarked name look the same here, so the read cannot prove
a failure). So this transform answers True or None only.
Limits: completeness needs pageInfo; when hasNextPage is true (Integration-Service merged the pages and
nulled endCursor) the read is complete only with an integer count and at least that many nodes.
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


METHOD = "listConsoleAdmins"
VENDOR = "Rubrik"
PRODUCT = "Rubrik Security Cloud"
FIELD = "usersInCurrentAndDescendantOrganization"
ROLE_LABEL = "an RSC administrator role"

ADMIN_IDENTITY = {"LOCAL": "local", "CLIENT": "service", "PAT": "service", "SUPPORT": "service",
                  "SSO": "sso", "LDAP": "directory"}


def graphql_errors(body):
    """Messages of GraphQL errors on the users field or on the whole request."""
    out = []
    errs = body.get("errors") if isinstance(body, dict) else None
    if not isinstance(errs, list):
        return out
    for e in errs:
        if not isinstance(e, dict):
            out.append(str(e)[:300])
            continue
        path = e.get("path")
        top = path[0] if isinstance(path, list) and len(path) > 0 else None
        if top is None or top == FIELD:
            out.append(str(e.get("message", ""))[:300])
    return out


def users_connection(body):
    """(nodes, None) for a complete read of the users connection, else (None, reason).

    Integration-Service cursor pagination merges the pages into one nodes list, keeps page-1 pageInfo
    with endCursor nulled, and adds pageInfo.truncated when maxPages stopped it."""
    if not isinstance(body, dict):
        return None, "the response is not a GraphQL object"
    root = body.get("data")
    if not isinstance(root, dict):
        root = body if FIELD in body else None
    if root is None:
        return None, "no GraphQL data in the response"
    conn = root.get(FIELD)
    if not isinstance(conn, dict) or not isinstance(conn.get("nodes"), list):
        return None, "no " + FIELD + ".nodes list in the response"
    nodes = conn.get("nodes")
    info = conn.get("pageInfo")
    if not isinstance(info, dict):
        return None, "no pageInfo, so a complete read cannot be shown"
    if info.get("truncated") is True:
        return None, "the user list was truncated at the page limit; the remaining pages were not read"
    if info.get("hasNextPage") is True and info.get("endCursor") is not None:
        return None, "only the first page of users was read"
    if info.get("hasNextPage") not in (True, False):
        return None, "pageInfo.hasNextPage is missing, so a complete read cannot be shown"
    count = conn.get("count")
    has_count = isinstance(count, int) and not isinstance(count, bool)
    if info.get("hasNextPage") is True and not has_count:
        return None, ("pageInfo.hasNextPage is true and no count was returned, so the merged pages cannot be shown "
                      "to be complete")
    if has_count and len(nodes) < count:
        return None, "read " + str(len(nodes)) + " of " + str(count) + " users; the rest were not read"
    for n in nodes:
        if not isinstance(n, dict):
            return None, "a user entry is not an object"
    return nodes, None


#: Whole words of a role name that name an administrator role (Super Admin, COHESITY_ADMIN, Backup Admins).
ROLE_ADMIN_WORDS = ("admin", "admins", "administrator", "administrators", "superadmin", "sysadmin")
#: A qualifier written directly before the admin word makes it a non-admin role (Non-Admin Viewer, No Admin
#: Access, NonAdmin). Elsewhere in the name it does not (Admin (no delete) is still an admin role).
ROLE_NEGATIONS = ("non", "no", "not")
#: Words that make the whole role read-only (Admin Read Only, ReadOnlyAdmin, View-Only Admin).
ROLE_READ_ONLY = ("readonly", "viewonly")
#: Endings of a joined role-name word that name an administrator role (TenantAdmin, HeliosAdmins).
ROLE_ADMIN_ENDINGS = ("administrators", "administrator", "admins", "admin")


def role_names_admin(name):
    """True when a role name names an administrator role in whole words (or a joined ending such as
    TenantAdmin), the admin word is not directly negated (non admin, no admin, nonadmin), and the role is not
    read-only or view-only."""
    words = [w for w in re.split(r"[^a-z0-9]+", str(name or "").lower()) if w]
    for i in range(len(words)):
        nxt = words[i + 1] if i + 1 < len(words) else ""
        if words[i] in ROLE_READ_ONLY or (words[i] in ("read", "view") and nxt == "only"):
            return False
    found = False
    for i in range(len(words)):
        w = words[i]
        prev = words[i - 1] if i > 0 else ""
        stem = None
        if w in ROLE_ADMIN_WORDS:
            stem = ""
        else:
            for e in ROLE_ADMIN_ENDINGS:
                if w.endswith(e) and len(w) > len(e):
                    stem = w[:-len(e)]
                    break
        if stem is None:
            continue
        if prev in ROLE_NEGATIONS or stem in ROLE_NEGATIONS or stem in ROLE_READ_ONLY or stem in ("read", "view"):
            continue
        found = True
    return found


def is_admin(node):
    """True / False, or None when the roles field is missing (the read cannot say)."""
    if node.get("isAccountOwner") is True:
        return True
    roles = node.get("roles")
    if not isinstance(roles, list):
        return None
    for r in roles:
        if not isinstance(r, dict):
            continue
        if r.get("isOrgAdmin") is True:
            return True
        if role_names_admin(r.get("name")):
            return True
    return False


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
            return not_measured(validation, "The response body is empty; nothing was read from Rubrik Security Cloud.")
        why = envelope_error(body)
        if why and not (isinstance(body, dict) and isinstance(body.get("data"), dict)):
            return not_measured(validation, "Rubrik Security Cloud: " + why + ". This is a credential or reachability "
                                "result, not a finding.", "Check the RSC URL and service account in the integration settings.")
        errs = graphql_errors(body)
        if errs:
            return not_measured(validation, "Rubrik Security Cloud returned a GraphQL error for the user list: " +
                                "; ".join(errs), "Grant the RSC service account read access to Users and Roles.")
        nodes, why = users_connection(body)
        if why:
            return not_measured(validation, "Rubrik Security Cloud: " + why + ".")
        admins = []
        for n in nodes:
            if str(n.get("status") or "").upper() == "DEACTIVATED":
                continue
            admin = is_admin(n)
            if admin is None:
                return not_measured(validation, "A user entry carries no roles list, so who administers the console "
                                    "cannot be read.")
            if not admin:
                continue
            domain = str(n.get("domain") or "").upper()
            identity = ADMIN_IDENTITY.get(domain, "unknown")
            names = [n.get("email"), n.get("username")]
            admins.append({"name": first_name(names), "class": classify(names, "user", identity)})
        return verdict(validation, admins, ROLE_LABEL, {"usersRead": len(nodes)})
    except Exception as e:
        return not_measured(validation, "Transformation error: " + str(e)[:300])
