"""
Transformation: isMFAEnforcedForUsers
Vendor: Microsoft Azure AD
Category: Identity / MFA

Evaluates if MFA is enforced for all users by checking that MFA methods are enabled
at the tenant level and conditional access policies require MFA for all users.

Input (merged workflow): {"authMethodsPolicy": GET /v1.0/policies/authenticationMethodsPolicy,
"conditionalAccessPolicies": GET /v1.0/identity/conditionalAccess/policies}.

Not evaluated (value None, dataCollection.status "error"):
- no Microsoft MFA method is enabled but an external authentication method (for example Cisco
  Duo, @odata.type externalAuthenticationMethodConfiguration) is: the factor is enforced by that
  provider, which Entra cannot grade (J.J., 3 Oct 2026; same rule as authtypesallowed.py and
  entra_strongauth_methods.py). It is never a FAIL. Seen at one estate, where a tenant
  that requires Duo through Conditional Access read "No MFA authentication methods enabled";
- no method that targets members is enabled: nothing at all, or only Email one-time passcode with an
  empty includeTargets list, which reaches B2B guests only (J.J., 3 Oct and 5 Oct 2026). The methods
  policy then does not govern member sign-in (per-user MFA or security defaults may), so it is not
  evidence either way. Guest Email OTP still fails authTypesAllowed. Same rule as
  874a78ff/ismfaenforcedforusers.py (TX #965);
- the authentication methods policy or the Conditional Access policies were not read (error
  envelope, no authenticationMethodConfigurations array, no policy list), or input validation
  failed: a read that failed is not evidence either way.

FAIL stays only when both were read and they show no MFA: no Microsoft MFA method, no external
method and some other member-targeted method enabled (for example SMS, voice or member Email OTP), or, with no external method enabled, no enabled Conditional Access
policy requiring MFA for users. An external method (e.g. Duo) with no Conditional Access policy
requiring MFA reads not evaluated, not FAIL.
"""

import json
from datetime import datetime

# Two independent switches (4 Oct 2026). With EXCLUDE_RISK_CONDITIONED = False and ALL_USERS_TARGET_MODE = "off" the
# output is byte-identical to the behaviour before they existed. J.J. chose (a) + (b-unevaluated) on 4 Oct 2026:
# EXCLUDE_RISK_CONDITIONED = True, ALL_USERS_TARGET_MODE = "unevaluated".
#
# EXCLUDE_RISK_CONDITIONED: a policy with a non-empty signInRiskLevels or userRiskLevels condition fires only on
#   risk (for example the Microsoft-managed "Multifactor authentication and reauthentication for risky sign-ins"
#   policy, or a user-risk password-change policy), so it does not enforce MFA for users' sign-ins. When True,
#   such policies do not count.
# ALL_USERS_TARGET_MODE: "off" (default), "unevaluated" or "not_met". When not "off", a policy counts only if
#   conditions.users.includeUsers contains "All". Group-targeted policies are set aside (their reach is not read
#   here; entra_ca_mfa_coverage.py resolves group membership for the remote-access keys). Exclusions follow the
#   repo convention of entra_ca_mfa_coverage.py (master review, 3 Oct 2026): at most MAX_EXCLUDED_ACCOUNTS user
#   accounts excluded by name in total per policy (emergency-access / break-glass) are allowed; any excluded group,
#   directory role, guests or external users, or "All" in excludeUsers sets the policy aside.
#   - "not_met": with no counting policy left, the key reads False (as before for "no policy").
#   - "unevaluated": with MFA methods enabled and no counting policy left, but at least one policy set aside for
#     its target or its exclusions (not for risk), the key reads not evaluated: MFA is required only for groups
#     (or with exclusions) whose membership is not read, so coverage of all users cannot be confirmed. It never
#     reads False on group policies alone.
# Set-aside policies are named in the fail reason (at most SET_ASIDE_SHOWN, then "and N more"; names cut to
# SET_ASIDE_NAME_CHARS) and returned as policiesSetAside.
#
# Group membership (5 Oct 2026, J.J. "get them fixed"; ported from entra_ca_mfa_coverage.py, TX #870): when the
# merged input also carries the group-membership reads, in the same shapes entra_ca_mfa_coverage.py reads
#   "workforceUsers": the enabled Member accounts (GET /v1.0/users?$select=id,accountEnabled,userType&$filter=...),
#   "caPolicyGroups": {"groupIds": [{"id": ...}, ...]}, the group ids the enabled policies name,
#   "groupMembers": one GET /v1.0/groups/{id}/transitiveMembers/microsoft.graph.user?$select=id body per group id,
#                   paired with groupIds by position,
# the policies set aside only because they target groups are judged from membership. A policy counts towards
# group coverage only when it is enabled, grants MFA (and under operator OR offers no other control), applies to
# All cloud apps, is not risk-only, is narrowed by no platform, device filter, client type or location, includes no
# directory role, and excludes no group, role, guests or "All" (at most MAX_EXCLUDED_ACCOUNTS named accounts, in
# total across the counting policies). Together (a union) they cover the workforce when every enabled Member account
# is in an included group, is an included user, or is one of those excluded named accounts: the key reads True.
# Group math can pass the key. It fails the key only on the members-outside rule below. A list not read whole (an
# error, a vendor error returned as data, @odata.nextLink still present, paginationTruncated, an @odata.count that
# disagrees, an item with no id), lists that cannot be paired with the group ids, or a group read twice, keep the key
# not evaluated with the reason and counts. With none of the three keys present the output is byte-identical to
# before.
#
# Members outside (code owner ruling, 5 Oct 2026): when membership was read whole and some enabled Member accounts
# are reached by NO enabled Conditional Access policy that requires MFA, the key reads False and the fail reason
# gives the count. "Reached" is read generously, so a False is never a guess:
#   - every enabled policy whose grant includes MFA counts, even one narrowed by apps, platform, client type,
#     location or device, or offering another control under OR (it reaches the account for some sign-ins);
#     only risk-only policies (EXCLUDE_RISK_CONDITIONED) do not count;
#   - "All" users reaches everyone; an included group must have been read whole, or nothing fails;
#   - an excluded group or directory role whose members are not read excludes nobody;
#   - a policy whose grant asks for an authentication strength (Multifactor, Passwordless, Phishing-resistant or
#     custom) reaches its included users like one that asks for the built-in "mfa" control;
#   - any MFA policy that includes a directory role keeps the key not evaluated: its holders are not read, so a
#     member counted as outside may be covered by it;
#   - accounts left outside only because a policy excludes them by name are break-glass when there are at most
#     MAX_EXCLUDED_ACCOUNTS of them, and are not counted as outside.
# Other evidence, read only when the merged input carries it:
#   "securityDefaults": GET /v1.0/policies/identitySecurityDefaultsEnforcementPolicy. Enabled (or not read whole):
#                       no False; the key stays not evaluated (security defaults are not graded here);
#   "perUserMfaStates": a Graph list of {"id", "perUserMfaState"} (GET /beta/users/{id}/authentication/requirements,
#                       one item per user). Only "enforced" covers that account ("enabled" means enrolled, and legacy
#                       clients can still sign in with a password); a list not read whole means no False. When CA
#                       group coverage plus enforced per-user MFA covers every enabled Member, the key passes.
MFA_PER_USER_STATES = ("enforced",)
EXCLUDE_RISK_CONDITIONED = True
ALL_USERS_TARGET_MODE = "unevaluated"
RISK_REASON = "fires only on sign-in or user risk"
MAX_EXCLUDED_ACCOUNTS = 2
SET_ASIDE_SHOWN = 5
SET_ASIDE_NAME_CHARS = 80
USER_KEYWORDS = ("all", "none", "guestsorexternalusers")
GROUP_REASON = "targets groups, not all users"
MEMBERSHIP_KEYS = ("workforceUsers", "caPolicyGroups", "groupMembers")


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for _ in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None, api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {
                "status": "error" if (api_errors or []) else "success",
                "errors": api_errors or []
            },
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", [])
            },
            "transformation": {
                "status": "error" if (transformation_errors or []) else "success",
                "errors": transformation_errors or [],
                "inputSummary": input_summary or {}
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or []
            },
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "isMFAEnforcedForUsers",
                "vendor": "Microsoft",
                "category": "Identity"
            }
        }
    }


def is_external_method(method):
    """An Entra external authentication method (EAM), for example Cisco Duo."""
    return "externalauthenticationmethodconfiguration" in str(method.get('@odata.type') or '').lower()


def not_evaluated(criteriaKey, reason, validation, input_summary=None, extra=None, findings=None):
    result = {criteriaKey: None}
    if extra:
        result.update(extra)
    return create_response(
        result=result,
        validation=validation,
        input_summary=input_summary,
        additional_findings=findings,
        api_errors=[reason]
    )


def short_name(value):
    name = str(value)
    return name if len(name) <= SET_ASIDE_NAME_CHARS else name[:SET_ASIDE_NAME_CHARS - 3] + "..."


def risk_conditioned(conditions):
    for key in ("signInRiskLevels", "userRiskLevels"):
        levels = conditions.get(key)
        if isinstance(levels, list) and len(levels) > 0:
            return True
    return False


def all_users_exclusions(users):
    """What an "All users" policy excludes beyond at most MAX_EXCLUDED_ACCOUNTS named accounts; '' when nothing."""
    found = []
    excluded = users.get("excludeUsers")
    if excluded is not None and not isinstance(excluded, list):
        return "users in a list that cannot be read"
    raw = [str(v).strip().lower() for v in (excluded or [])]
    if "all" in raw:
        found.append("all users")
    if "guestsorexternalusers" in raw or users.get("excludeGuestsOrExternalUsers"):
        found.append("guests or external users")
    if users.get("excludeGroups"):
        found.append("a group")
    if users.get("excludeRoles"):
        found.append("a directory role")
    named = [v for v in raw if v and v not in USER_KEYWORDS]
    if len(named) > MAX_EXCLUDED_ACCOUNTS:
        found.append(f"{len(named)} user accounts (more than {MAX_EXCLUDED_ACCOUNTS})")
    return ", ".join(found)


def set_aside_reason(conditions, users, targets_all):
    if EXCLUDE_RISK_CONDITIONED and risk_conditioned(conditions):
        return RISK_REASON
    if ALL_USERS_TARGET_MODE in ("unevaluated", "not_met"):
        if not targets_all:
            return GROUP_REASON
        excluded = all_users_exclusions(users)
        if excluded:
            return "excludes " + excluded
    return ""


def set_aside_text(entries):
    shown = ['"' + name + '" (' + why + ")" for name, why in entries[:SET_ASIDE_SHOWN]]
    more = len(entries) - SET_ASIDE_SHOWN
    return "policies set aside: " + ", ".join(shown) + (f" and {more} more" if more > 0 else "")


def as_dict(value):
    return value if isinstance(value, dict) else {}


def as_list(value):
    return value if isinstance(value, list) else []


def lowered(values):
    return [str(v).strip().lower() for v in as_list(values)]


def present(value):
    """True when a condition value says something: not None or False, and not an empty list, dict or string."""
    if value is None or value is False:
        return False
    if isinstance(value, (list, dict, str)):
        return len(value) > 0
    return True


def mfa_only_grant(policy):
    """'mfa' is required: under operator OR no other control could satisfy the policy instead."""
    grant = as_dict(policy.get("grantControls"))
    controls = lowered(grant.get("builtInControls"))
    if "mfa" not in controls:
        return False
    others = [c for c in controls if c != "mfa"] + lowered(grant.get("customAuthenticationFactors")) \
        + lowered(grant.get("termsOfUse"))
    if str(grant.get("operator") or "").upper() == "OR" and others:
        return False
    return True


def unnarrowed(conditions):
    """No device filter, platform scope, client-type narrowing or location scope (entra_ca_mfa_coverage.py)."""
    device_filter = as_dict(as_dict(conditions.get("devices")).get("deviceFilter"))
    if str(device_filter.get("rule") or "").strip():
        return False
    platforms = as_dict(conditions.get("platforms"))
    included_platforms = lowered(platforms.get("includePlatforms"))
    if (included_platforms and "all" not in included_platforms) or present(platforms.get("excludePlatforms")):
        return False
    apps = lowered(conditions.get("clientAppTypes"))
    if apps and "all" not in apps and not ("browser" in apps and "mobileappsanddesktopclients" in apps):
        return False
    locations = conditions.get("locations")
    if isinstance(locations, dict):
        include = lowered(locations.get("includeLocations"))
        if include and "all" not in include:
            return False
    return True


def group_candidate(policy, conditions, users):
    """A group-targeted MFA policy whose reach the membership read can decide (see the header)."""
    if all_users_exclusions(users) or present(users.get("includeRoles")):
        return False
    if not as_list(users.get("includeGroups")):
        return False
    if "all" not in lowered(as_dict(conditions.get("applications")).get("includeApplications")):
        return False
    if risk_conditioned(conditions) or not mfa_only_grant(policy):
        return False
    return unnarrowed(conditions)


def unpaged(page):
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
    """The pages of a Graph list read whole; None when absent, an error, a vendor error returned as data, still paged,
    truncated, missing a value array, or with an @odata.count that disagrees with the items."""
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
    """Lower-case ids of the enabled Member accounts, read whole; None otherwise. Disabled or guest items are left
    out whatever the filter did; an item that does not say both is not read."""
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


def refused_403(body):
    """True when a member read came back as Graph's 403 Authorization_RequestDenied (returned as data)."""
    holder = as_dict(as_dict(body).get("vendorErrorAsResponse"))
    return str(holder.get("status") or "") == "403"


def read_memberships(data):
    """({lower-case group id: member ids, or None when that list was not read whole}, refused count). Lists that
    cannot be paired with the group ids, or a fan-out that reports item errors or truncation, pair nothing."""
    ids = as_dict(data.get("caPolicyGroups")).get("groupIds")
    bodies = data.get("groupMembers")
    out = {}
    refused = 0
    if not isinstance(ids, list) or not isinstance(bodies, list) or len(ids) != len(bodies):
        return out, refused
    if data.get("itemErrors") or data.get("iterateTruncated") is True:
        return out, refused
    seen = set()
    for index in range(len(ids)):
        entry = ids[index]
        gid = str((entry.get("id") if isinstance(entry, dict) else entry) or "").strip().lower()
        if not gid:
            continue
        if gid in seen:
            out[gid] = None
            continue
        seen.add(gid)
        if refused_403(bodies[index]):
            refused = refused + 1
        out[gid] = read_ids(bodies[index])
    return out, refused


def object_ids(values):
    out = set()
    for value in as_list(values):
        text = str(value or "").strip().lower()
        if text and text not in USER_KEYWORDS:
            out.add(text)
    return out


def group_coverage(data, candidates):
    """Whether the candidate policies together reach every enabled Member account. Returns a dict of counts
    (no user ids or names). coversAll is True only on a whole read with nobody left outside."""
    workforce = read_workforce(data.get("workforceUsers"))
    memberships, refused = read_memberships(data)
    covered = set()
    exempt = set()
    unread = set()
    used = set()
    contributing = []
    for name, users in candidates:
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
        excluded = object_ids(users.get("excludeUsers"))
        covered = covered | (reached - excluded)
        exempt = exempt | excluded
        contributing.append(name)
    out = {"policies": contributing, "memberListRead": workforce is not None, "groupsRead": len(used),
           "groupsUnread": len(unread), "groupReadsRefused": refused, "membersTotal": None, "membersCovered": None,
           "excludedCount": None, "uncoveredCount": None, "excludedAccountsTotal": len(exempt), "coversAll": False}
    if workforce is None:
        return out
    inside = workforce & covered
    excluded_members = (workforce & exempt) - inside
    outside = workforce - inside - excluded_members
    out["membersTotal"] = len(workforce)
    out["membersCovered"] = len(inside)
    out["excludedCount"] = len(excluded_members)
    out["uncoveredCount"] = len(outside)
    out["coversAll"] = (bool(workforce) and not outside and bool(contributing)
                        and len(exempt) <= MAX_EXCLUDED_ACCOUNTS)
    return out


def defaults_block(data):
    """A reason the members-outside rule may not fail the key because of security defaults; '' when it may."""
    if "securityDefaults" not in data:
        return ""
    defaults = data.get("securityDefaults")
    enabled = as_dict(defaults).get("isEnabled")
    if isinstance(enabled, str) and enabled.strip().lower() in ("true", "false"):
        enabled = enabled.strip().lower() == "true"
    if not isinstance(enabled, bool) or "error" in as_dict(defaults) or "vendorErrorAsResponse" in as_dict(defaults):
        return "the security defaults policy was not read whole"
    if enabled:
        return "security defaults are enabled, and they are not graded here"
    return ""


def per_user_mfa(data):
    """(lower-case ids with per-user MFA enforced or enabled, '' or a reason the list cannot be used). An absent key
    gives (set(), '')."""
    if "perUserMfaStates" not in data:
        return set(), ""
    pages = list_pages(data.get("perUserMfaStates"))
    if pages is None:
        return set(), "the per-user MFA list was not read whole"
    ids = set()
    for page in pages:
        for item in page["value"]:
            uid = str(as_dict(item).get("id") or "").strip().lower()
            if not uid:
                return set(), "the per-user MFA list was not read whole"
            if str(as_dict(item).get("perUserMfaState") or "").strip().lower() in MFA_PER_USER_STATES:
                ids.add(uid)
    return ids, ""


def requires_mfa_reach(policy):
    """For the members-outside rule only: the grant asks for MFA, either the built-in "mfa" control or an
    authentication strength (built-in Multifactor, Passwordless or Phishing-resistant MFA, or a custom strength).
    Generous on purpose: counting a policy can only remove members from "outside", never add a False."""
    grant = as_dict(policy.get("grantControls"))
    if "mfa" in lowered(grant.get("builtInControls")):
        return True
    strength = grant.get("authenticationStrength")
    return isinstance(strength, dict) and bool(strength)


def members_outside(data, policies):
    """({'outside': ids, 'membersTotal': n}, '') for the enabled Member accounts that no enabled MFA-granting policy
    reaches (generous reach, see the header), or (None, reason) when that cannot be decided."""
    workforce = read_workforce(data.get("workforceUsers"))
    if not workforce:
        return None, "the enabled member account list was not read whole"
    memberships, refused = read_memberships(data)
    if refused:
        return None, "a group member read was refused"
    reached = set()
    named_excluded = set()
    for policy in policies:
        if not isinstance(policy, dict) or policy.get("state") != "enabled":
            continue
        if not requires_mfa_reach(policy):
            continue
        conditions = as_dict(policy.get("conditions"))
        if EXCLUDE_RISK_CONDITIONED and risk_conditioned(conditions):
            continue
        users = as_dict(conditions.get("users"))
        if present(users.get("includeRoles")):
            return None, ("an MFA policy includes a directory role, and role holders are not read, so members "
                          "counted as outside may hold that role and be covered")
        include = lowered(users.get("includeUsers"))
        reach = set(workforce) if "all" in include else (object_ids(users.get("includeUsers")) & workforce)
        for gid in object_ids(users.get("includeGroups")):
            members = memberships.get(gid)
            if members is None:
                return None, "the member list of an included group was not read whole"
            reach = reach | (members & workforce)
        if not reach:
            continue
        for gid in object_ids(users.get("excludeGroups")):
            members = memberships.get(gid)
            if members is not None:
                reach = reach - members
        excluded = object_ids(users.get("excludeUsers"))
        named_excluded = named_excluded | excluded
        reached = reached | (reach - excluded)
    outside = workforce - reached
    break_glass = outside & named_excluded
    if len(break_glass) <= MAX_EXCLUDED_ACCOUNTS:
        outside = outside - break_glass
    return {"outside": outside, "membersTotal": len(workforce)}, ""


def candidate_reach(data, candidates):
    """Lower-case ids the counting group-scoped policies include (included groups or users); None when an included
    group's member list was not read whole."""
    memberships, _ = read_memberships(data)
    covered = set()
    for _, users in candidates:
        reach = object_ids(users.get("includeUsers"))
        for gid in object_ids(users.get("includeGroups")):
            members = memberships.get(gid)
            if members is None:
                return None
            reach = reach | members
        covered = covered | reach
    return covered


def coverage_detail(coverage):
    """Why the membership read did not show every enabled Member account covered."""
    notes = []
    if coverage["groupReadsRefused"]:
        notes.append(f"Microsoft Graph refused {coverage['groupReadsRefused']} group member read(s) (403): grant the "
                     "app GroupMember.Read.All (or Group.Read.All / Directory.Read.All) and admin consent")
    elif coverage["groupsUnread"]:
        notes.append(f"the member list of {coverage['groupsUnread']} included group(s) was not read whole")
    if not coverage["memberListRead"]:
        notes.append("the enabled member account list was not read whole (User.Read.All)")
    elif not coverage["membersTotal"]:
        notes.append("no enabled member accounts were read")
    elif coverage["uncoveredCount"]:
        notes.append(f"{coverage['uncoveredCount']} of {coverage['membersTotal']} enabled members are outside the "
                     "included groups that could be read, but each is reached by another MFA policy that is narrowed "
                     "or offers another control: add them to a group the policy includes, or attest")
    if coverage["excludedAccountsTotal"] > MAX_EXCLUDED_ACCOUNTS:
        notes.append(f"the policies exclude {coverage['excludedAccountsTotal']} named accounts in total (more than "
                     f"{MAX_EXCLUDED_ACCOUNTS} emergency-access accounts)")
    if not coverage["policies"] and not notes:
        notes.append("no included group yielded a member list")
    return "; ".join(notes) or "coverage of all users cannot be confirmed"


# #101: findings name the affected accounts (same shape as legacyauthblocked.py). The first reason names
# at most MAX_NAMED, then "and N more"; inputSummary.affectedAccounts carries at most MAX_AFFECTED, with
# the full count in affectedAccountCount. The verdict never reads them.
MAX_NAMED = 20
MAX_AFFECTED = 50


def name_list(items):
    """At most MAX_NAMED identifiers, then 'and N more'."""
    shown = ", ".join(items[:MAX_NAMED])
    if len(items) > MAX_NAMED:
        shown = shown + " and " + str(len(items) - MAX_NAMED) + " more"
    return shown


def affected_line(scope, affected, total, what):
    """One line naming the tool and its scope: 'Microsoft Entra ID (<scope>): N of M <what>: a, b and K more'."""
    return "Microsoft Entra ID (%s): %d of %d %s: %s" % (scope, len(affected), total, what, name_list(affected))


def with_affected(summary, affected):
    summary["affectedAccounts"] = affected[:MAX_AFFECTED]
    summary["affectedAccountCount"] = len(affected)
    return summary


EXCLUDE_FIELDS = [('excludeUsers', 'user'), ('excludeGroups', 'group'), ('excludeRoles', 'role')]
INCLUDE_FIELDS = [('includeUsers', 'user'), ('includeGroups', 'group'), ('includeRoles', 'role')]
# Graph keywords, not principals.
SPECIAL_PRINCIPALS = {'user:All', 'user:all', 'user:None', 'user:GuestsOrExternalUsers', 'group:All', 'role:All'}


def principals(users, fields):
    found = []
    for field, kind in fields:
        values = users.get(field) if isinstance(users, dict) else None
        if not isinstance(values, list):
            continue
        for value in values:
            if isinstance(value, str) and value.strip():
                found.append(kind + ":" + value.strip()[:64])
    return found


def mfa_coverage(user_conditions):
    """Per-principal coverage across the MFA-for-users policies (same rule as legacyauthblocked.py): a
    principal is covered when at least one policy includes it (directly or through All users) and that same
    policy does not exclude it. Returns (uncovered principals, principals named, include scope or None when a
    policy targets all users). Group and role membership is not expanded."""
    all_users = False
    scope = []
    rules = []
    candidates = []
    for users in user_conditions:
        excluded = set(principals(users, EXCLUDE_FIELDS))
        included = principals(users, INCLUDE_FIELDS)
        includes_all = "user:All" in included or "user:all" in included
        if includes_all:
            all_users = True
        rules.append((includes_all, set(included), excluded))
        for x in included:
            if x not in scope:
                scope.append(x)
        for x in list(excluded) + included:
            if x not in SPECIAL_PRINCIPALS and x not in candidates:
                candidates.append(x)
    uncovered = sorted(
        x for x in candidates
        if not any((includes_all or x in included) and x not in excluded
                   for includes_all, included, excluded in rules)
    )
    return uncovered, len(candidates), (None if all_users else sorted(scope))


def members_outside_verdict(criteriaKey, data, policies, candidates, coverage, enabled_methods, validation,
                            input_summary, details):
    """The members-outside rule (header). A response, or None to keep the not-evaluated path."""
    if coverage["groupReadsRefused"] or coverage["groupsUnread"] or not coverage["memberListRead"]:
        return None
    found, why = members_outside(data, policies)
    if found is None:
        details["membersOutsideUndecided"] = why
        return None
    per_user, per_user_why = per_user_mfa(data)
    outside = found["outside"] - per_user
    total = found["membersTotal"]
    workforce = read_workforce(data.get("workforceUsers")) or set()
    if per_user and not per_user_why:
        covered = candidate_reach(data, candidates)
        exempt = set()
        for _, users in candidates:
            exempt = exempt | object_ids(users.get("excludeUsers"))
        if covered is not None and len(exempt) <= MAX_EXCLUDED_ACCOUNTS and workforce <= (covered | per_user | exempt):
            details["groupCoverage"] = coverage
            details["perUserMfaCovered"] = len((workforce - covered - exempt) & per_user)
            input_summary["membersTotal"] = total
            result = {criteriaKey: True}
            result.update(details)
            return create_response(
                result=result, validation=validation,
                pass_reasons=[f"MFA methods enabled: {', '.join(enabled_methods)}",
                              f"MFA enforced for all {total} enabled member accounts: group-scoped Conditional Access "
                              f"policies cover {total - details['perUserMfaCovered']} of them and per-user MFA covers "
                              f"the other {details['perUserMfaCovered']} (group membership and per-user MFA read)"],
                input_summary=input_summary)
    if not outside:
        return None
    blocked = defaults_block(data) or per_user_why
    details["membersOutsideCount"] = len(outside)
    if blocked:
        details["membersOutsideUndecided"] = blocked
        return None
    input_summary["membersTotal"] = total
    input_summary["membersWithoutMfaPolicy"] = len(outside)
    result = {criteriaKey: False}
    result.update(details)
    word = "account is" if len(outside) == 1 else "accounts are"
    return create_response(
        result=result, validation=validation,
        pass_reasons=[f"MFA methods enabled: {', '.join(enabled_methods)}"],
        fail_reasons=[f"{len(outside)} of {total} enabled member {word} not covered by any enabled Conditional Access "
                      "policy that requires MFA: they are in none of the groups or user lists those policies include "
                      "(group membership read), so MFA is not enforced for them"],
        recommendations=["Add these members to a group an MFA policy includes, or target an MFA policy at All users"],
        input_summary=input_summary)


def transform(input):
    criteriaKey = "isMFAEnforcedForUsers"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return not_evaluated(criteriaKey, "Input validation failed: the MFA evidence was not read", validation)

        if not isinstance(data, dict) or not data:
            return not_evaluated(
                criteriaKey,
                "Microsoft Graph returned no MFA evidence (authentication methods policy and Conditional Access policies)",
                validation)

        if 'error' in data:
            error_info = data.get('error')
            code = error_info.get('code', 'unknown') if isinstance(error_info, dict) else 'unknown'
            return not_evaluated(criteriaKey, f"Microsoft Graph API error: {str(code)[:80]}", validation)

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        # 1. Check authentication methods policy — are MFA methods enabled at the tenant level?
        # Graph returns a configuration object for every method it knows, enabled or not, so a
        # missing or empty array means the policy was not read (not that no method is enabled).
        auth_methods = data.get('authMethodsPolicy')
        method_configs = auth_methods.get('authenticationMethodConfigurations') if isinstance(auth_methods, dict) else None
        if not isinstance(method_configs, list) or not method_configs:
            return not_evaluated(
                criteriaKey,
                "The authentication methods policy was not read (no authenticationMethodConfigurations array), "
                "so the absence of an MFA method is not evidence that none is enabled",
                validation)

        ca_data = data.get('conditionalAccessPolicies')
        if isinstance(ca_data, list):
            policies = ca_data
        elif isinstance(ca_data, dict) and 'error' not in ca_data:
            policies = ca_data.get('value')
        else:
            policies = None
        if not isinstance(policies, list):
            return not_evaluated(
                criteriaKey,
                "The Conditional Access policies were not read (no policy list), so the absence of a policy "
                "requiring MFA is not evidence that none exists",
                validation)

        mfa_method_types = ['microsoftauthenticator', 'fido2', 'softwareoath', 'temporaryaccesspass']
        enabled_methods = []
        external_methods = []
        other_member_methods = []
        guest_only_email = False
        for method in method_configs:
            if not isinstance(method, dict):
                continue
            if str(method.get('state') or 'disabled').lower() != 'enabled':
                continue
            if is_external_method(method):
                external_methods.append(str(method.get('displayName') or method.get('id') or 'external method')[:60])
            elif str(method.get('id') or '').lower() in mfa_method_types:
                enabled_methods.append(str(method.get('id')))
            elif (str(method.get('id') or '').lower() == 'email' and isinstance(method.get('includeTargets'), list)
                    and len(method.get('includeTargets')) == 0):
                # Email OTP with no include targets reaches B2B guests only, not members.
                guest_only_email = True
            else:
                other_member_methods.append(str(method.get('id') or 'unknown')[:40])

        methods_available = len(enabled_methods) > 0

        # 2. Check conditional access policies — is MFA enforced for all users?
        policies_enforcing_mfa_all_users = []
        set_aside = []
        mfa_user_conditions = []
        group_candidates = []

        for policy in policies:
            if not isinstance(policy, dict) or policy.get('state') != 'enabled':
                continue
            grant_controls = policy.get('grantControls') or {}
            built_in_controls = grant_controls.get('builtInControls') or []
            if 'mfa' not in built_in_controls:
                continue

            conditions = policy.get('conditions') or {}
            users = conditions.get('users') or {}
            include_users = users.get('includeUsers') or []
            include_groups = users.get('includeGroups') or []

            targets_all = 'All' in include_users or 'all' in include_users
            targets_groups = len(include_groups) > 0

            if targets_all or targets_groups:
                why = set_aside_reason(conditions, users, targets_all)
                if why:
                    set_aside.append((short_name(policy.get('displayName')), why))
                    if why == GROUP_REASON and group_candidate(policy, conditions, users):
                        group_candidates.append((short_name(policy.get('displayName')), users))
                    continue
                policies_enforcing_mfa_all_users.append(policy.get('displayName'))
                mfa_user_conditions.append(users)

        mfa_enforced_for_users = len(policies_enforcing_mfa_all_users) > 0
        input_summary = {
            "enabledMethods": len(enabled_methods),
            "externalMethods": external_methods,
            "mfaUserPolicies": len(policies_enforcing_mfa_all_users)
        }
        details = {
            "mfaMethodsAvailable": methods_available,
            "enabledMethods": enabled_methods,
            "externalMethods": external_methods,
            "policiesEnforcingMFAForUsers": policies_enforcing_mfa_all_users
        }
        if set_aside:
            details["policiesSetAside"] = [name + " (" + why + ")" for name, why in set_aside]

        # 3. An external authentication method (for example Cisco Duo) enforces its own factors,
        # which Entra cannot see. When it stands in for every Microsoft MFA method, the check is
        # not evaluated; it is never a FAIL (J.J., 3 Oct 2026).
        if not methods_available and external_methods:
            findings = []
            if mfa_enforced_for_users:
                findings.append("Conditional Access policies requiring MFA for users: "
                                + ", ".join(str(p)[:80] for p in policies_enforcing_mfa_all_users[:3]))
            return not_evaluated(
                criteriaKey,
                "MFA is provided by an external authentication method (e.g. Duo); Entra cannot grade it. "
                "Enabled external method(s): " + ", ".join(external_methods)
                + "; no Microsoft MFA method is enabled in the authentication methods policy",
                validation, input_summary=input_summary, extra=details, findings=findings)

        # 3b. No method that targets members is enabled (nothing, or guest-only Email OTP): the methods
        # policy does not govern member sign-in, so it is not evidence either way (J.J., 3 and 5 Oct 2026).
        if not methods_available and not external_methods and not other_member_methods:
            details["guestOnlyEmail"] = guest_only_email
            return not_evaluated(
                criteriaKey,
                "No authentication method that targets members is enabled"
                + (" (Email one-time passcode is enabled for B2B guests only)" if guest_only_email else "")
                + ", so the authentication methods policy does not show whether MFA is enforced for users",
                validation, input_summary=input_summary, extra=details)

        scope_unknown = [(name, why) for name, why in set_aside if why != RISK_REASON]
        membership_note = ""
        if (ALL_USERS_TARGET_MODE == "unevaluated" and methods_available and not mfa_enforced_for_users
                and scope_unknown and any(k in data for k in MEMBERSHIP_KEYS)):
            if group_candidates:
                coverage = group_coverage(data, group_candidates)
                details["groupCoverage"] = coverage
                if coverage["coversAll"]:
                    details["policiesEnforcingMFAForUsers"] = coverage["policies"]
                    input_summary["mfaUserPolicies"] = len(coverage["policies"])
                    input_summary["membersTotal"] = coverage["membersTotal"]
                    result = {criteriaKey: True}
                    result.update(details)
                    return create_response(
                        result=result,
                        validation=validation,
                        pass_reasons=[
                            f"MFA methods enabled: {', '.join(enabled_methods)}",
                            "MFA enforced for users via group-scoped policies "
                            + ", ".join('"' + n + '"' for n in coverage["policies"][:SET_ASIDE_SHOWN])
                            + f": all {coverage['membersTotal']} enabled member accounts are covered, "
                            f"{coverage['membersCovered']} through the included groups or included users and "
                            f"{coverage['excludedCount']} excluded by name (group membership read)"],
                        input_summary=input_summary)
                outcome = members_outside_verdict(criteriaKey, data, policies, group_candidates, coverage,
                                                  enabled_methods, validation, input_summary, details)
                if outcome is not None:
                    return outcome
                membership_note = "; group membership was read: " + coverage_detail(coverage)
            else:
                membership_note = ("; group membership was read, but no set-aside policy is one it can decide (each "
                                   "is narrowed by apps, platform, client type, location or risk, includes a role, "
                                   "or excludes a group, role or guests)")
        if (ALL_USERS_TARGET_MODE == "unevaluated" and methods_available and not mfa_enforced_for_users
                and scope_unknown):
            names = ", ".join('"' + name + '"' for name, _ in scope_unknown[:SET_ASIDE_SHOWN])
            more = len(scope_unknown) - SET_ASIDE_SHOWN
            return not_evaluated(
                criteriaKey,
                "MFA is required only by policies scoped to groups or with exclusions (" + names
                + (f" and {more} more" if more > 0 else "") + ")"
                + (membership_note if membership_note else "; group membership is not read")
                + ", so coverage of all users cannot be confirmed; " + set_aside_text(set_aside),
                validation, input_summary=input_summary, extra=details)

        is_enforced = methods_available and mfa_enforced_for_users
        uncovered, named_total, mfa_scope = mfa_coverage(mfa_user_conditions)
        input_summary = with_affected(dict(input_summary), uncovered)
        if mfa_enforced_for_users and mfa_scope is not None:
            input_summary["mfaScope"] = mfa_scope[:MAX_NAMED]

        if methods_available:
            pass_reasons.append(f"MFA methods enabled: {', '.join(enabled_methods)}")
        else:
            fail_reasons.append("No MFA authentication methods enabled at the tenant level")
            recommendations.append("Enable MFA methods (Microsoft Authenticator, FIDO2, or Software OATH) in authentication methods policy")

        if mfa_enforced_for_users:
            pass_reasons.append(f"MFA enforced for users via {len(policies_enforcing_mfa_all_users)} policies: {', '.join(str(p) for p in policies_enforcing_mfa_all_users[:3])}")
        else:
            fail_reasons.append("No enabled conditional access policies requiring MFA for all users"
                                + ("; " + set_aside_text(set_aside) if set_aside else ""))
            recommendations.append("Create a conditional access policy requiring MFA that targets All Users or relevant groups")

        if is_enforced and (uncovered or mfa_scope is not None):
            line = ""
            if uncovered:
                line = "; " + affected_line("Conditional Access policies requiring MFA for users", uncovered,
                                            named_total, "users, groups or roles named in those policies are "
                                            "covered by none of them")
            if mfa_scope is not None:
                line = (line + "; no MFA policy targets all users, MFA reaches only: "
                        + (name_list(mfa_scope) if mfa_scope else "no one named"))
            pass_reasons[0] = pass_reasons[0] + line
            recommendations.append("Review the accounts named above: remove each MFA exclusion that is not a "
                                   "documented break-glass account, and target the MFA policy at All users")

        result = {criteriaKey: is_enforced}
        result.update(details)
        return create_response(
            result=result,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary=input_summary
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: None},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            api_errors=[f"Transformation error: {str(e)}"]
        )
