"""isRDPProtected and isMFARequiredForRemoteAccess for Microsoft Entra ID (Azure AD One-Click), from the
Conditional Access policy list (GET /v1.0/identity/conditionalAccess/policies) and, when the workflow supplies
them, the tenant's group list with membership rules (GET /v1.0/groups?$select=id,displayName,groupTypes,
membershipRule,membershipRuleProcessingState) and the security defaults policy
(GET /v1.0/policies/identitySecurityDefaultsEnforcementPolicy, merged under "securityDefaults"; Policy.Read.All,
the same permission the Conditional Access list already needs).

Coverage (2 Oct 2026, J.J.): entra_ca_tenantwide_mfa.py left every group-scoped or client-type-split policy
"not evaluated". This version decides coverage where the data allows it, and stays not evaluated otherwise:
- a policy scoped to user groups covers all users when every included group is a dynamic group whose rule
  selects every (enabled, member) user and whose rule processing is On. Assigned-membership groups, or a group
  missing from the supplied group list, keep the policy "partial" (membership is not read here);
- policies with the same full user reach that differ only in client app types count together: browser plus
  mobileAppsAndDesktopClients across two enabled MFA policies is the same as "all";
- excluded users and groups are allowed and listed, as before.
Nothing here can pass a tenant on data it did not read.

Security defaults (3 Oct 2026, J.J.): when no Conditional Access policy is enabled, the tenant's security defaults
policy is read. Security defaults and enabled Conditional Access policies are mutually exclusive in Entra.
Security defaults never pass either key: they require administrators to use MFA at every sign-in, but other users
are challenged only when Microsoft judges a sign-in risky, not at every remote sign-in, and they do not target the
Remote Desktop apps. When isEnabled is true, both keys read not evaluated with that reason and the honest next step
(add a Conditional Access policy requiring MFA, or attest). When it is false, the keys stay not evaluated, because
per-user MFA may still apply and is not read here. An absent, error or unrecognised security defaults body changes nothing (not evaluated, as
before). It is never consulted when any Conditional Access policy is enabled.

Group membership (3 Oct 2026, J.J.): a workforce MFA policy scoped to user groups, and narrowed by nothing else (no
platform, client-type or device-filter narrowing, and in force off the corporate network), is decided from the
groups' membership when the workflow supplies it:
- "workforceUsers": the enabled member accounts (GET /v1.0/users?$select=id,accountEnabled,userType&$filter=
  accountEnabled eq true and userType eq 'Member'&$count=true, ConsistencyLevel: eventual), read whole;
- "caPolicyGroups": {"groupIds": [{"id": ...}, ...]}, the group ids the enabled policies include or exclude;
- "groupMembers": one GET /v1.0/groups/{id}/transitiveMembers/microsoft.graph.user?$select=id body per group id,
  in the same order (nested groups count, because the read is transitive).
Such policies, together (a union, as client types already are), cover the workforce when every enabled member
account is in at least one included group or listed as an included user, or is excluded by one of the policies
(excluded accounts are allowed, as for "All users" policies, and counted). Group math can pass a key; it never
fails one. When members are left outside the included groups the key stays not evaluated and says how many, and
any list not read whole (an error, a vendor error returned as data, @odata.nextLink still present, an
@odata.count that disagrees with the items, an item with no id, or member lists that cannot be paired with the
group ids) is not read: a policy that includes an unread group keeps only the groups that were read, and a policy
that excludes an unread group counts for nothing. The output carries counts only (membersTotal, membersCovered,
excludedCount, uncoveredCount) and the group names; never user ids, names or UPNs.

Why a new file: isrdpprotected.py and ismfarequiredforremoteaccess.py count ANY enabled policy that
grants mfa (or block) for all apps, whoever it targets and whatever else it is conditioned on. On
2026-09-29 "Block legacy authentication" passed isRDPProtected at one tenant, and "Require MFA for Guest
Users" and Microsoft-managed "MFA for risky sign-ins" passed both keys at others. None of them says that
users must pass MFA.

A workforce MFA policy is enabled (report-only does not enforce), covers all apps (includeApplications
"All"; isRDPProtected also accepts the Remote Desktop / Windows Cloud Login app ids), targets all users
or user groups (not only admin roles, guests or named users), does not fire only for some risk levels,
and carries a real MFA grant ("mfa" in builtInControls or an authenticationStrength, and under operator
OR no other control that could satisfy the policy instead).

Value, per key:
- true: a workforce MFA policy targets all users (includeUsers "All"; excluded accounts are allowed and
  listed) with no platform, device-filter or client-type narrowing (client types "all", or both browser
  and mobileAppsAndDesktopClients), and is in force off the corporate network (no location condition,
  or includeLocations "All" with trusted or named locations excluded);
- true, as well, when group-scoped workforce MFA policies are shown by the membership read to reach every enabled
  member account (above);
- not evaluated (dataCollection error, None): the only workforce MFA policies are scoped to user groups,
  platforms, client types or named locations, so whether they reach every user and sign-in cannot be
  read from this list (or the membership read leaves members outside the groups, or was not read whole); or no policy is enabled (security defaults on challenge non-admins by risk only; with
  them off or unread, per-user MFA may apply and is not read here);
- false: policies are enabled and none of them is a workforce MFA policy.
If either key is not evaluated the whole run reports a dataCollection error, so neither key reads a
verdict from an incomplete picture. An error or unrecognised body, or a list that still carries
@odata.nextLink (pages left unread), is not evaluated.
"""

import json
from datetime import datetime


KEYS = ("isRDPProtected", "isMFARequiredForRemoteAccess")
SECURITY_DEFAULTS_POLICY_ID = "00000000-0000-0000-0000-000000000005"
RDP_APP_IDS = ("a4a365df-50f1-4397-bc59-1a1564b8bb9c", "270efc09-cd0d-444b-a71f-39af4910ec45",
               "c0d2a505-13b8-4ae0-aa9e-cddd5eab0b12")


def extract_input(value):
    if isinstance(value, (str, bytes)):
        value = json.loads(value.decode("utf-8") if isinstance(value, bytes) else value)
    if isinstance(value, dict) and "data" in value and "validation" in value:
        return value["data"], value["validation"]
    data = value
    for attempt in range(3):
        if not isinstance(data, dict):
            break
        nested = None
        for key in ("api_response", "response", "result", "apiResponse", "Output"):
            if isinstance(data.get(key), (dict, list)):
                nested = data[key]
                break
        if nested is None:
            break
        data = nested
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation, errors=(), passed=(), failed=(), summary=None):
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if errors else "success", "errors": list(errors)},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {"status": "success", "errors": [], "inputSummary": summary or {}},
            "evaluation": {
                "passReasons": list(passed),
                "failReasons": list(failed) + list(errors),
                "recommendations": [],
                "additionalFindings": [],
            },
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "2.0",
                "transformationId": "entra_ca_mfa_coverage",
                "vendor": "Microsoft Entra ID",
                "category": "Identity and Access Management",
            },
        },
    }


def as_dict(value):
    return value if isinstance(value, dict) else {}


def as_list(value):
    return value if isinstance(value, list) else []


def lowered(values):
    return [str(v).lower() for v in as_list(values)]


def requires_mfa(policy):
    grant = as_dict(policy.get("grantControls"))
    controls = lowered(grant.get("builtInControls"))
    strength = as_dict(grant.get("authenticationStrength")).get("id")
    has_mfa = "mfa" in controls or bool(strength)
    if not has_mfa:
        return False
    others = [c for c in controls if c != "mfa"] + lowered(grant.get("customAuthenticationFactors")) \
        + lowered(grant.get("termsOfUse"))
    if str(grant.get("operator") or "").upper() == "OR" and others:
        return False
    return True


ALL_RISK_LEVELS = set(["high", "medium", "low", "none"])


def risk_only(conditions):
    """True when the policy fires only for some risk levels (all four levels, 'none' included, is no narrowing)."""
    for risk in ("signInRiskLevels", "userRiskLevels", "servicePrincipalRiskLevels"):
        levels = set(lowered(conditions.get(risk)))
        if levels and not ALL_RISK_LEVELS.issubset(levels):
            return True
    return False


def unnarrowed(conditions):
    device_filter = as_dict(as_dict(conditions.get("devices")).get("deviceFilter"))
    if str(device_filter.get("rule") or "").strip():
        return False
    platforms = as_dict(conditions.get("platforms"))
    included_platforms = lowered(platforms.get("includePlatforms"))
    if (included_platforms and "all" not in included_platforms) or as_list(platforms.get("excludePlatforms")):
        return False
    apps = lowered(conditions.get("clientAppTypes"))
    if apps and "all" not in apps and not ("browser" in apps and "mobileappsanddesktopclients" in apps):
        return False
    return True


def covers_remote(conditions):
    locations = conditions.get("locations")
    if not isinstance(locations, dict):
        return True
    include = lowered(locations.get("includeLocations"))
    return not include or "all" in include


ALL_USER_ATOMS = set([
    "user.accountenabled-eqtrue",
    "user.objectid-nenull",
    'user.usertype-eq"member"',
])


def rule_atoms(rule):
    """Split a dynamic membership rule into normalised atoms joined by -and; None if it uses anything else."""
    text = "".join(str(rule or "").lower().split())
    if not text:
        return None
    parts = text.split("-and")
    atoms = []
    for part in parts:
        atom = part
        while atom.startswith("(") and atom.endswith(")"):
            atom = atom[1:-1]
        if "-or" in atom or "(" in atom or ")" in atom or not atom:
            return None
        atoms.append(atom.replace("'", '"'))
    return atoms


def is_all_users_group(group):
    """A dynamic group whose rule selects every enabled member user, with rule processing On."""
    if not isinstance(group, dict):
        return False
    if "dynamicmembership" not in lowered(group.get("groupTypes")):
        return False
    if str(group.get("membershipRuleProcessingState") or "").lower() != "on":
        return False
    atoms = rule_atoms(group.get("membershipRule"))
    return bool(atoms) and all(atom in ALL_USER_ATOMS for atom in atoms)


def user_scope(conditions, groups=None):
    """'all' for every user, 'groups' for user groups, else '' (admins, roles, guests, named users)."""
    users = as_dict(conditions.get("users"))
    if "all" in lowered(users.get("includeUsers")):
        return "all"
    included = as_list(users.get("includeGroups"))
    if included and not as_list(users.get("includeRoles")):
        if isinstance(groups, dict) and all(is_all_users_group(groups.get(str(g).lower())) for g in included):
            return "all"
        return "groups"
    return ""


def client_types(conditions):
    """The client app types a policy covers, as a set of 'browser' and 'mobileappsanddesktopclients'."""
    apps = lowered(conditions.get("clientAppTypes"))
    if not apps or "all" in apps:
        return set(["browser", "mobileappsanddesktopclients"])
    return set(a for a in apps if a in ("browser", "mobileappsanddesktopclients"))


def narrowed_only_by_client_type(conditions):
    """Unnarrowed except for client app types (no device filter, no platform scope)."""
    device_filter = as_dict(as_dict(conditions.get("devices")).get("deviceFilter"))
    if str(device_filter.get("rule") or "").strip():
        return False
    platforms = as_dict(conditions.get("platforms"))
    included_platforms = lowered(platforms.get("includePlatforms"))
    if (included_platforms and "all" not in included_platforms) or as_list(platforms.get("excludePlatforms")):
        return False
    return True


def classify(policy, app_ids, groups=None):
    """'full', 'partial' (an MFA policy for the workforce whose reach cannot be judged here) or ''."""
    if str(policy.get("state") or "").lower() != "enabled" or not requires_mfa(policy):
        return ""
    conditions = as_dict(policy.get("conditions"))
    included_apps = lowered(as_dict(conditions.get("applications")).get("includeApplications"))
    if "all" not in included_apps and not any(app in included_apps for app in app_ids):
        return ""
    scope = user_scope(conditions, groups)
    if not scope or risk_only(conditions):
        return ""
    if scope == "all" and unnarrowed(conditions) and covers_remote(conditions):
        return "full"
    return "partial"


def client_union_full(policies, app_ids, groups):
    """Enabled MFA policies that each reach every user, off-network, narrowed only by client app type, and
    whose client types together cover both browser and desktop/mobile clients."""
    covered = set()
    names = []
    for policy in policies:
        if classify(policy, app_ids, groups) != "partial":
            continue
        conditions = as_dict(policy.get("conditions"))
        if user_scope(conditions, groups) != "all" or not covers_remote(conditions):
            continue
        if not narrowed_only_by_client_type(conditions):
            continue
        covered |= client_types(conditions)
        names.append(str(policy.get("displayName") or policy.get("id")))
    if covered >= set(["browser", "mobileappsanddesktopclients"]) and len(names) > 1:
        return names
    return []


def read_security_defaults(body):
    """True or False from GET /v1.0/policies/identitySecurityDefaultsEnforcementPolicy; None when the body is absent,
    an error, not that policy, or carries no readable isEnabled."""
    if isinstance(body, list) and len(body) == 1:
        body = body[0]
    if not isinstance(body, dict) or "error" in body:
        return None
    context = str(body.get("@odata.context") or "").lower()
    if "identitysecuritydefaultsenforcementpolicy" not in context \
            and str(body.get("id") or "") != SECURITY_DEFAULTS_POLICY_ID:
        return None
    value = body.get("isEnabled")
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text == "true":
        return True
    if text == "false":
        return False
    return None


def unpaged(page):
    """True when a Graph list page says no pages are left unread."""
    next_link = page.get("@odata.nextLink")
    return not (isinstance(next_link, str) and next_link.strip() not in ("", "None", "null"))


def declared_count(value):
    """An @odata.count as an int; None when absent; -1 when present but unreadable (never matches a list)."""
    if value is None:
        return None
    if isinstance(value, bool):
        return -1
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if text.isdigit():
        return int(text)
    return -1


def list_pages(body):
    """The pages of a Graph list read whole (one page, or a list of pages); None when absent, an error, a vendor
    error returned as data, still paged, missing a value array, or with an @odata.count that disagrees with the
    number of items."""
    pages = body if isinstance(body, list) else [body]
    if not pages:
        return None
    count = 0
    for page in pages:
        if not isinstance(page, dict) or "error" in page or "vendorErrorAsResponse" in page:
            return None
        if page.get("paginationTruncated") is True or not unpaged(page):
            return None
        if not isinstance(page.get("value"), list):
            return None
        count = count + len(page["value"])
    declared = declared_count(pages[0].get("@odata.count"))
    if declared is not None and declared != count:
        return None
    return pages


def read_ids(body):
    """Lower-case ids from a Graph list read whole; None when it was not, or an item carries no id."""
    pages = list_pages(body)
    if pages is None:
        return None
    ids = set()
    for page in pages:
        for item in page["value"]:
            if not isinstance(item, dict) or not str(item.get("id") or "").strip():
                return None
            ids.add(str(item["id"]).strip().lower())
    return ids


def read_workforce(body):
    """Lower-case ids of the enabled member accounts in GET /v1.0/users (filtered to accountEnabled true and
    userType Member); None when the list was not read whole or an item does not say whether it is an enabled
    member. Items that say they are disabled or guests are left out, whatever the filter did."""
    pages = list_pages(body)
    if pages is None:
        return None
    ids = set()
    for page in pages:
        for item in page["value"]:
            if not isinstance(item, dict) or not str(item.get("id") or "").strip():
                return None
            enabled = item.get("accountEnabled")
            kind = item.get("userType")
            if not isinstance(enabled, bool) or not isinstance(kind, str):
                return None
            if enabled and kind.strip().lower() == "member":
                ids.add(str(item["id"]).strip().lower())
    return ids


def read_memberships(group_ids, member_bodies):
    """{lower-case group id: set of transitive member user ids, or None when that list was not read whole}.
    The member bodies are paired with the group ids by position, so lists of different lengths pair nothing,
    and a group id read twice is not trusted."""
    holder = as_dict(group_ids)
    ids = holder.get("groupIds")
    out = {}
    if not isinstance(ids, list) or not isinstance(member_bodies, list) or len(ids) != len(member_bodies):
        return out
    seen = set()
    for index in range(len(ids)):
        entry = ids[index]
        gid = entry.get("id") if isinstance(entry, dict) else entry
        key = str(gid or "").strip().lower()
        if not key:
            continue
        if key in seen:
            out[key] = None
            continue
        seen.add(key)
        out[key] = read_ids(member_bodies[index])
    return out


USER_KEYWORDS = ("all", "none", "guestsorexternalusers")


def object_ids(values):
    """Lower-case object ids from an includeUsers/excludeUsers/includeGroups/excludeGroups list (keywords dropped)."""
    out = set()
    for value in as_list(values):
        text = str(value or "").strip().lower()
        if text and text not in USER_KEYWORDS:
            out.add(text)
    return out


def group_name(gid, groups):
    group = as_dict(groups.get(gid)) if isinstance(groups, dict) else {}
    return str(group.get("displayName") or gid)


def group_candidates(enabled, app_ids, groups):
    """Workforce MFA policies scoped to user groups and narrowed by nothing else: no platform, client-type or
    device-filter narrowing, and in force off the corporate network."""
    out = []
    for policy in enabled:
        if classify(policy, app_ids, groups) != "partial":
            continue
        conditions = as_dict(policy.get("conditions"))
        if user_scope(conditions, groups) != "groups":
            continue
        if not unnarrowed(conditions) or not covers_remote(conditions):
            continue
        out.append(policy)
    return out


def group_coverage(candidates, workforce, memberships, groups):
    """Whether group-scoped MFA policies together reach every enabled member account. Counts only."""
    covered = set()
    exempt = set()
    used = set()
    unread = set()
    contributing = []
    for policy in candidates:
        users = as_dict(as_dict(policy.get("conditions")).get("users"))
        excluded = object_ids(users.get("excludeUsers"))
        blocked = False
        for gid in sorted(object_ids(users.get("excludeGroups"))):
            members = memberships.get(gid)
            if members is None:
                unread.add(gid)
                blocked = True
            else:
                excluded = excluded | members
                used.add(gid)
        if blocked:
            continue
        reached = object_ids(users.get("includeUsers"))
        for gid in sorted(object_ids(users.get("includeGroups"))):
            members = memberships.get(gid)
            if members is None:
                unread.add(gid)
            else:
                reached = reached | members
                used.add(gid)
        if not reached:
            continue
        covered = covered | (reached - excluded)
        exempt = exempt | excluded
        contributing.append(str(policy.get("displayName") or policy.get("id")))
    out = {"policies": contributing, "memberListRead": workforce is not None,
           "groupsUsed": sorted(group_name(g, groups) for g in used),
           "groupsUnread": sorted(group_name(g, groups) for g in unread),
           "membersTotal": None, "membersCovered": None, "excludedCount": None, "uncoveredCount": None,
           "coversAll": False}
    if workforce is None:
        return out
    in_policies = workforce & covered
    excluded_members = (workforce & exempt) - in_policies
    outside = workforce - in_policies - excluded_members
    out["membersTotal"] = len(workforce)
    out["membersCovered"] = len(in_policies)
    out["excludedCount"] = len(excluded_members)
    out["uncoveredCount"] = len(outside)
    out["coversAll"] = bool(workforce) and not outside and bool(contributing)
    return out


def evaluate(policies, groups=None, security_defaults=None, membership=None):
    """membership: None when the workflow supplied no membership read, else (workforce ids or None, memberships)."""
    enabled = [p for p in policies if str(p.get("state") or "").lower() == "enabled"]
    result = {"enabledPolicyCount": len(enabled), "policyCount": len(policies),
              "groupListRead": isinstance(groups, dict), "groupsRead": len(groups) if isinstance(groups, dict) else 0,
              "securityDefaultsEnabled": security_defaults}
    for key, app_ids, names in (("isRDPProtected", RDP_APP_IDS, "rdpPolicies"),
                                ("isMFARequiredForRemoteAccess", (), "remoteAccessPolicies")):
        full = [p for p in enabled if classify(p, app_ids, groups) == "full"]
        partial = [p for p in enabled if classify(p, app_ids, groups) == "partial"]
        union = [] if full else client_union_full(enabled, app_ids, groups)
        result[names] = [str(p.get("displayName") or p.get("id")) for p in full] or union
        result[names + "Partial"] = [str(p.get("displayName") or p.get("id")) for p in partial]
        coverage = None
        if not full and not union:
            candidates = group_candidates(enabled, app_ids, groups) if membership is not None else []
            if candidates:
                coverage = group_coverage(candidates, membership[0], membership[1], groups)
                result[names + "GroupCoverage"] = coverage
        if full or union:
            result[key] = True
        elif coverage is not None and coverage["coversAll"]:
            result[names] = coverage["policies"]
            result[key] = True
        elif partial or not enabled:
            result[key] = None
        else:
            result[key] = False
    return result


def read_groups(group_data):
    """{lower-case id: group} from GET /v1.0/groups (one page, a page list, or a merged value list).
    None when absent, an error, or still paged (@odata.nextLink), so no group resolves from a partial list."""
    pages = group_data if isinstance(group_data, list) else [group_data]
    out = {}
    for page in pages:
        if not isinstance(page, dict) or "error" in page:
            return None
        next_link = page.get("@odata.nextLink")
        if isinstance(next_link, str) and next_link.strip() not in ("", "None", "null"):
            return None
        values = page.get("value")
        if not isinstance(values, list):
            return None
        for group in values:
            if isinstance(group, dict) and group.get("id"):
                out[str(group["id"]).lower()] = group
    return out


def group_detail(coverage):
    """The reason a group-scoped policy set was not shown to reach every enabled member account."""
    if not isinstance(coverage, dict):
        return "whether they reach every user and sign-in cannot be read here"
    unread = coverage["groupsUnread"]
    unread_note = ""
    if unread:
        unread_note = f" (member lists not read whole for {len(unread)} group(s): {', '.join(unread)})"
    if not coverage["memberListRead"]:
        return ("the enabled member account list could not be read whole, so whether the included groups reach "
                "every user cannot be read here" + unread_note)
    if not coverage["membersTotal"]:
        return "no enabled member accounts were read, so whether the included groups reach every user cannot be read here"
    if coverage["uncoveredCount"]:
        where = "the included groups that could be read" if unread else "the included groups"
        return (f"{coverage['uncoveredCount']} of {coverage['membersTotal']} enabled members are outside {where}"
                + unread_note + ". Group membership never fails this check: add them to a group the policy includes, "
                "or attest")
    return "whether they reach every user and sign-in cannot be read here" + unread_note


def transform(input):
    try:
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            raise ValueError("Input validation failed")
        groups = None
        security_defaults = None
        membership = None
        if isinstance(data, dict) and "conditionalAccessPolicies" in data:
            group_data = data.get("groups")
            security_defaults = read_security_defaults(data.get("securityDefaults"))
            if any(k in data for k in ("workforceUsers", "caPolicyGroups", "groupMembers")):
                membership = (read_workforce(data.get("workforceUsers")),
                              read_memberships(data.get("caPolicyGroups"), data.get("groupMembers")))
            data = data.get("conditionalAccessPolicies")
            if isinstance(data, list) and len(data) == 1 and isinstance(data[0], dict):
                data = data[0]
            groups = read_groups(group_data)
        if not isinstance(data, dict) or "error" in data:
            raise ValueError("Microsoft did not return the Conditional Access policy list")
        policies = data.get("value")
        if not isinstance(policies, list) or any(not isinstance(p, dict) for p in policies):
            raise ValueError("The Conditional Access response carries no value array of policies")
        if "@odata.context" not in data and not policies:
            raise ValueError("An empty body with no @odata.context is not a Conditional Access policy list")
        next_link = data.get("@odata.nextLink")
        if isinstance(next_link, str) and next_link.strip() not in ("", "None", "null"):
            raise ValueError("The policy list has more pages than were read (@odata.nextLink still present)")
        result = evaluate(policies, groups, security_defaults, membership)
        passed = []
        failed = []
        errors = []
        for key, names in (("isRDPProtected", "rdpPolicies"), ("isMFARequiredForRemoteAccess", "remoteAccessPolicies")):
            coverage = result.get(names + "GroupCoverage")
            if result[key] is True and isinstance(coverage, dict) and coverage["coversAll"]:
                passed.append(key + ": MFA required for all apps by group-scoped policies " + ", ".join(result[names])
                              + f": all {coverage['membersTotal']} enabled member accounts are in the included "
                              f"groups ({', '.join(coverage['groupsUsed'])}) or excluded by the policies "
                              f"({coverage['excludedCount']} excluded)")
            elif result[key] is True:
                passed.append(key + ": MFA required of all users for all apps by " + ", ".join(result[names]))
            elif result[key] is False:
                failed.append(key + ": no enabled policy requires MFA of the workforce for all apps (only admins, roles, "
                              "guests, named users, risky sign-ins or specific apps) "
                              f"({result['enabledPolicyCount']} of {result['policyCount']} policies enabled)")
            elif result[names + "Partial"]:
                errors.append(key + ": MFA for all apps is required by policies scoped to user groups, platforms, "
                              "client types or named locations (" + ", ".join(result[names + "Partial"])
                              + "); " + group_detail(coverage))
            elif result["securityDefaultsEnabled"] is True and key == "isRDPProtected":
                errors.append(key + ": Security defaults are on, but they do not target Remote Desktop sign-ins and "
                              "challenge non-admins by risk only. Add a Conditional Access policy requiring MFA for "
                              "Remote Desktop, or attest.")
            elif result["securityDefaultsEnabled"] is True:
                errors.append(key + ": Security defaults are on: admins always need MFA; other users are challenged "
                              "by risk, not on every remote sign-in. Add a Conditional Access policy requiring MFA, "
                              "or attest.")
            elif result["securityDefaultsEnabled"] is False:
                errors.append(key + ": no Conditional Access policy is enabled and security defaults are off; "
                              "per-user MFA may apply and is not read here")
            else:
                errors.append(key + ": no Conditional Access policy is enabled; security defaults or per-user MFA "
                              "may apply and are not read here")
        return create_response(result, validation, errors=errors, passed=passed, failed=failed, summary=result)
    except Exception as error:
        result = {}
        for key in KEYS:
            result[key] = None
        return create_response(
            result,
            {"status": "failed", "errors": [str(error)], "warnings": []},
            errors=[str(error)],
        )
