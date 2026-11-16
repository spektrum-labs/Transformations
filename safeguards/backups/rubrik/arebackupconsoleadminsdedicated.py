"""
Transformation: areBackupConsoleAdminsDedicated
Vendor: Rubrik  |  Category: Backup  |  Product: Rubrik Security Cloud (RSC)
Claim (IAM-004): the backup console is administered only by dedicated admin accounts, never a person's
everyday SSO identity.
API Source: listConsoleAdmins (POST https://<account>.my.rubrik.com/api/graphql, read-only query)
    query RscConsoleAdmins($first: Int, $after: String) {
      usersInCurrentAndDescendantOrganization(first: $first, after: $after) {
        count pageInfo { hasNextPage endCursor }
        nodes { id domain status isAccountOwner roles { id name isOrgAdmin } } }
      groupsInCurrentAndDescendantOrganization(first: 200) {
        count pageInfo { hasNextPage endCursor } nodes { groupId roles { id name isOrgAdmin } } } }
Schema: rubrikinc/rubrik-developer-center docs/Rubrik-Security-Cloud-API/schemas/20260914.graphql
    (type User: domain UserDomainEnum! = LOCAL | SSO | LDAP | CLIENT | PAT | SUPPORT; status UserStatus! =
    ACTIVE | DEACTIVATED | UNKNOWN; roles [Role!]! with isOrgAdmin. type Group: SSO or directory groups that
    hold roles; the query leaves out groups with no role. Group members appear as users only after they sign
    in, so an admin role held by a group reaches identities the user list does not show.)
Rule (separate identity per person): an administrator is an active user who is the account owner, holds a role
with isOrgAdmin, or holds a role whose name names an admin role in whole words (Administrator, Backup Admins;
not Non-Admin Viewer, No Admin Access or Admin Read Only). Each person must administer the console through an
identity that is separate from their everyday sign-in: a LOCAL user is a console-only account (separate by
construction) and CLIENT, PAT and SUPPORT users are non-person accounts. An SSO or LDAP user signs in with a
directory identity, and RSC does not show whether that identity is a separate admin account or the person's
everyday one. Account names are not read: a naming convention cannot prove which it is.
True: the user and group reads are complete, no group holds an administrator role, and every administrator is a
LOCAL console account or a non-person account.
None (not evaluated): any administrator signs in with an SSO or LDAP identity, or with an unknown domain; a group
holds an administrator role; empty, error or partial input; a GraphQL error on either field; or no
administrator in the read.
Rubrik never returns False: nothing in the RSC read shows that a directory identity is a person's everyday
account (J.J.'s ruling of 6 Oct 2026 still holds).
Reasons and the input summary carry counts only, never account names or email addresses; the query does not
ask RSC for them.
Limits: completeness needs pageInfo; when hasNextPage is true on the user list (Integration-Service merged the
pages and nulled endCursor) the read is complete only with an integer count and at least that many nodes. The
group list is not paged by Integration-Service, so it must fit on one page.
"""
import json
import re
from datetime import datetime, timezone

KEY = "areBackupConsoleAdminsDedicated"

#: The criterion this file answers. None means "not measured", never "failed".
NONE_MEANS_NOT_EVALUATED = (KEY,)

WRAPPERS = ("apiResponse", "api_response", "response", "result", "Output", "_response_data")

METHOD = "listConsoleAdmins"
VENDOR = "Rubrik"
PRODUCT = "Rubrik Security Cloud"
FIELD = "usersInCurrentAndDescendantOrganization"
GROUPS_FIELD = "groupsInCurrentAndDescendantOrganization"

#: How each RSC user domain signs in: a console-only account, a non-person account, or a directory identity.
SEPARATE_DOMAINS = ("LOCAL",)
NON_PERSON_DOMAINS = ("CLIENT", "PAT", "SUPPORT")
DIRECTORY_DOMAINS = ("SSO", "LDAP")

RECOMMENDATION = ("Give each administrator a separate admin identity: a local RSC console account per person, or a "
                  "service account for automation, and remove administrator roles from SSO and LDAP identities and "
                  "groups. Where administrators must sign in through the identity provider, attest that each is a "
                  "separate admin account there, not the person's everyday sign-in.")


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



def graphql_errors(body):
    """Messages of GraphQL errors on the users or groups field or on the whole request."""
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
        if top is None or top in (FIELD, GROUPS_FIELD):
            out.append(str(e.get("message", ""))[:300])
    return out


def connection(body, field, label):
    """(nodes, None) for a complete read of one GraphQL connection, else (None, reason).

    Integration-Service cursor pagination merges the pages into one nodes list, keeps page-1 pageInfo
    with endCursor nulled, and adds pageInfo.truncated when maxPages stopped it."""
    if not isinstance(body, dict):
        return None, "the response is not a GraphQL object"
    root = body.get("data")
    if not isinstance(root, dict):
        root = body if field in body else None
    if root is None:
        return None, "no GraphQL data in the response"
    conn = root.get(field)
    if not isinstance(conn, dict) or not isinstance(conn.get("nodes"), list):
        return None, "no " + field + ".nodes list in the response"
    nodes = conn.get("nodes")
    info = conn.get("pageInfo")
    if not isinstance(info, dict):
        return None, "no " + label + " pageInfo, so a complete read cannot be shown"
    if info.get("truncated") is True:
        return None, "the " + label + " list was truncated at the page limit; the remaining pages were not read"
    if info.get("hasNextPage") is True and info.get("endCursor") is not None:
        return None, "only the first page of " + label + "s was read"
    if info.get("hasNextPage") not in (True, False):
        return None, "pageInfo.hasNextPage is missing on the " + label + " list, so a complete read cannot be shown"
    count = conn.get("count")
    has_count = isinstance(count, int) and not isinstance(count, bool)
    if info.get("hasNextPage") is True and not has_count:
        return None, ("pageInfo.hasNextPage is true on the " + label + " list and no count was returned, so the "
                      "merged pages cannot be shown to be complete")
    if has_count and len(nodes) < count:
        return None, "read " + str(len(nodes)) + " of " + str(count) + " " + label + "s; the rest were not read"
    for n in nodes:
        if not isinstance(n, dict):
            return None, "a " + label + " entry is not an object"
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



def verdict(validation, counts, summary):
    """The criterion from complete user and group reads. counts: administrators by sign-in kind."""
    admins = counts["separate"] + counts["nonPerson"] + counts["directory"] + counts["unknown"]
    if counts["adminGroups"] > 0:
        return not_measured(validation,
                            str(counts["adminGroups"]) + " SSO or directory group(s) hold an RSC administrator role. "
                            "Every member of such a group can administer the console with the identity it signs in "
                            "with, and RSC does not list those members until they sign in, so a separate admin "
                            "identity per person cannot be shown.", RECOMMENDATION, summary)
    if admins == 0:
        return not_measured(validation,
                            "The read listed no account holding an RSC administrator role. Every console has at least "
                            "one administrator, so the administrators were not in what was read; the control's state "
                            "is unknown.", "Give the integration account read access to the console's users and roles.",
                            summary)
    if counts["directory"] > 0:
        return not_measured(validation,
                            str(counts["directory"]) + " of " + str(admins) + " console administrators sign in with an "
                            "SSO or LDAP identity. RSC does not show whether that identity is a separate admin account "
                            "or the person's everyday sign-in, so a separate admin identity per person cannot be "
                            "shown.", RECOMMENDATION, summary)
    if counts["unknown"] > 0:
        return not_measured(validation,
                            str(counts["unknown"]) + " of " + str(admins) + " console administrators have a user domain "
                            "this check does not recognise, so how they sign in cannot be shown.", RECOMMENDATION,
                            summary)
    return create_response(
        result={KEY: True},
        validation=validation,
        pass_reasons=["All " + str(admins) + " console administrators use an identity separate from any everyday "
                      "sign-in: " + str(counts["separate"]) + " local RSC console account(s) and " +
                      str(counts["nonPerson"]) + " non-person account(s); no SSO or directory group holds an "
                      "administrator role."],
        input_summary=summary,
    )


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
            return not_measured(validation, "Rubrik Security Cloud returned a GraphQL error for the user or group list: " +
                                "; ".join(errs), "Grant the RSC service account read access to Users, "
                                "Groups and Roles.")
        nodes, why = connection(body, FIELD, "user")
        if why:
            return not_measured(validation, "Rubrik Security Cloud: " + why + ".")
        groups, why = connection(body, GROUPS_FIELD, "group")
        if why:
            return not_measured(validation, "Rubrik Security Cloud: " + why + ". Groups that hold an administrator "
                                "role must be read to show who can administer the console.",
                                "Grant the RSC service account read access to Groups and Roles.")
        counts = {"separate": 0, "nonPerson": 0, "directory": 0, "unknown": 0, "adminGroups": 0}
        for g in groups:
            admin = is_admin(g)
            if admin is None:
                return not_measured(validation, "A group entry carries no roles list, so whether it holds an "
                                    "administrator role cannot be read.")
            if admin:
                counts["adminGroups"] = counts["adminGroups"] + 1
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
            if domain in SEPARATE_DOMAINS:
                kind = "separate"
            elif domain in NON_PERSON_DOMAINS:
                kind = "nonPerson"
            elif domain in DIRECTORY_DOMAINS:
                kind = "directory"
            else:
                kind = "unknown"
            counts[kind] = counts[kind] + 1
        summary = {
            "usersRead": len(nodes),
            "groupsRead": len(groups),
            "consoleAdministrators": counts["separate"] + counts["nonPerson"] + counts["directory"] + counts["unknown"],
            "localConsoleAccounts": counts["separate"],
            "nonPersonAccounts": counts["nonPerson"],
            "directoryIdentities": counts["directory"],
            "unknownDomain": counts["unknown"],
            "adminGroups": counts["adminGroups"],
        }
        return verdict(validation, counts, summary)
    except Exception as e:
        return not_measured(validation, "Transformation error: " + str(e)[:300])
