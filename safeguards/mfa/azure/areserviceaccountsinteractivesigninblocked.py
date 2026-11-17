"""
Transformation: areServiceAccountsInteractiveSignInBlocked
Vendor: Microsoft Entra ID (One-Click)  |  Category: Identity and Access Management
Claim (IAM-001): service accounts cannot sign in interactively. In Entra ID that is an enabled Conditional Access
policy that blocks the account from every cloud app.

WHICH ACCOUNTS ARE SERVICE ACCOUNTS (WI-3c, product decision 16 Nov 2026, option a): by signal, not by group name.
Microsoft Graph has no service-account flag, and most tenants have no group named for them. An enabled Member
account is a service account when either holds:
  (a) sign-in signal: it has a non-interactive sign-in in the last SIGNAL_DAYS days and no interactive sign-in in
      that window (signInActivity.lastNonInteractiveSignInDateTime recent; lastSignInDateTime, which Microsoft
      records for interactive sign-ins only, null, absent or older than the window). This is the approved WI-3c
      option (a) rule. A service account is usually signed into interactively once at setup, so "never signed in"
      would miss most of them. A person whose devices refresh tokens but who has not signed in for SIGNAL_DAYS
      days is read as a service account too (a known limit of the approved rule);
  (b) MFA carve-out: an enabled Conditional Access policy that requires MFA of all cloud apps, and is not
      risk-only, would reach it but excludes it, by name (excludeUsers) or through an excluded group whose
      transitive members were read. A policy that never reached the account (admin-only, app-specific, or
      including other groups) is no carve-out.
Break-glass is worked out first: accounts an All-users MFA policy excludes by name, or through a group of at most
MAX_BREAK_GLASS members, that the sign-in signal did not find. They must keep interactive sign-in, so they are
never judged. A service account that no block policy covers is reported whatever the number of such accounts
(False, with a scope note). Only when every found service account is blocked and more than MAX_BREAK_GLASS such
accounts exist is the result not evaluated: they cannot be told from service accounts.
Conditional Access is also evaluated on non-interactive sign-ins, so a block that covers every location would break
a working workload. A block that leaves trusted locations open (includeLocations All, excludeLocations set) counts
as blocking: the account cannot sign in from anywhere else.

Source: workflow getServiceAccountSignInEvidence (One-Click), merging
    conditionalAccessPolicies  getConditionalAccessPolicies   GET /v1.0/identity/conditionalAccess/policies
    signInUsers                getUsersWithSignInActivity     GET /v1.0/users?$select=id,accountEnabled,userType,
                                                              signInActivity (AuditLog.Read.All, Entra ID P1)
    caPolicyGroups             getCAPolicyGroupIds            the group ids the enabled policies include or exclude
    groupMembers               getGroupTransitiveUsers        one transitive member read per group id, same order
"groups" (the old name-based read) is accepted and ignored.

An account is BLOCKED when at least one enabled policy (not report-only):
    - has grant control block, targets all cloud apps (includeApplications All, no excluded apps, no application
      filter), applies to every client app type, and has no other condition with a value (included locations other
      than All, platforms other than All, device filters, risk levels, authentication flows, or any condition this
      file does not know; excluded locations are allowed, the trusted-location exemption);
    - includes the account: All users, the account by id, or a group whose member list was read and holds it;
    - and does not exclude it: not by id, not through an excluded group that holds it. An excluded group whose
      members were not read, an excluded directory role, or excluded guests/external users may exclude it.
True: every service account is blocked, or none was found by either signal in a whole read (the reason states
the scope). False: at least one is not blocked; the reason gives the count and partial object ids, never names.
Not evaluated (None with a dataCollection error): an empty, error or unrecognised body; the policy list or the
user read missing, in error or truncated; a user without readable sign-in dates; a group the decision needs whose
member list was not read whole; or an account that a policy may or may not block.
"""
import json
import re
from datetime import datetime, timedelta, timezone

KEY = "areServiceAccountsInteractiveSignInBlocked"

#: The criterion this file answers. None means "not measured", never "failed".
NONE_MEANS_NOT_EVALUATED = (KEY,)

WRAPPERS = ("apiResponse", "api_response", "response", "result", "Output", "rawResponse")

PARTS = ("conditionalAccessPolicies", "signInUsers", "groups")

#: The sign-in signal window, in days.
SIGNAL_DAYS = 90
#: Accounts found only by the MFA carve-out are break-glass up to this many (entra_ca_mfa_coverage.py's bound).
MAX_BREAK_GLASS = 2
#: Partial object ids named in a reason, at most.
MAX_NAMED = 5
#: A Graph UTC timestamp: "2026-11-01T08:15:30Z", optionally with fractional seconds.
GRAPH_TIME = r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z$"


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


def has_part(cur):
    for p in PARTS:
        if p in cur:
            return True
    return False


def unwrap(raw):
    """(body, validation) with the Token-Service envelope and Integration-Service wrappers removed."""
    validation = {"status": "unknown", "errors": [], "warnings": ["Legacy input format - no schema validation performed"]}
    cur = to_obj(raw)
    if isinstance(cur, dict) and "validation" in cur and "data" in cur:
        if isinstance(cur.get("validation"), dict):
            validation = cur.get("validation")
        cur = to_obj(cur.get("data"))
    for depth in range(8):
        if not isinstance(cur, dict) or has_part(cur):
            break
        nxt = None
        for w in WRAPPERS:
            if isinstance(cur.get(w), (dict, str)):
                nxt = to_obj(cur.get(w))
                break
        if nxt is None and isinstance(cur.get("data"), (dict, str)):
            nxt = to_obj(cur.get("data"))
        if nxt is None:
            break
        cur = nxt
    return cur, validation


def envelope_error(obj):
    """A short reason when obj is an error envelope rather than a Graph body, else None."""
    if not isinstance(obj, dict):
        return None
    err = obj.get("error")
    if err is True or isinstance(err, (str, dict)):
        detail = obj.get("message") or err
        if isinstance(detail, dict):
            detail = detail.get("message") or detail.get("code") or json.dumps(detail)[:200]
        return "the call did not return data: " + str(detail)[:300]
    code = obj.get("statusCode")
    if code is None:
        code = obj.get("status_code")
    if isinstance(code, int) and not isinstance(code, bool) and code >= 400:
        return "the call returned HTTP " + str(code)
    return None


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, api_errors=None):
    """Standardized transformation response (CONTRIBUTING.md)."""
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if api_err_list else "success", "errors": api_err_list},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {"status": "success", "errors": [], "inputSummary": input_summary or {}},
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": [],
            },
            "metadata": {
                "evaluatedAt": datetime.now(timezone.utc).isoformat(),
                "schemaVersion": "2.0",
                "transformationId": KEY,
                "vendor": "Microsoft Entra ID",
                "category": "Identity and Access Management",
            },
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


def workflow_truncated(body, key):
    """True when the workflow reported that the part under key was cut off at its page limit (reportPagination)."""
    if not isinstance(body, dict):
        return False
    stats = to_obj(body.get("paginationStats"))
    if isinstance(stats, dict):
        entry = to_obj(stats.get(key))
        if isinstance(entry, dict):
            flag = entry.get("paginationTruncated")
            if flag is True or str(flag).strip().lower() == "true":
                return True
    flag = body.get("paginationTruncated")
    return flag is True or str(flag).strip().lower() == "true"


def graph_collection(part, what):
    """(items, None) for a complete Graph collection read, else (None, reason)."""
    cur = to_obj(part)
    for depth in range(5):
        if cur is None:
            return None, what + ": the part is missing or empty"
        if isinstance(cur, list):
            return None, what + ": a bare list carries no proof that every page was read"
        if not isinstance(cur, dict):
            return None, what + ": the part is not a JSON object"
        why = envelope_error(cur)
        if why:
            return None, what + ": " + why
        if isinstance(cur.get("value"), list):
            break
        nxt = None
        for w in WRAPPERS:
            if isinstance(cur.get(w), (dict, str)):
                nxt = to_obj(cur.get(w))
                break
        if nxt is None:
            return None, what + ": no value collection in the response"
        cur = nxt
    if not (isinstance(cur, dict) and isinstance(cur.get("value"), list)):
        return None, what + ": no value collection in the response"
    nxt_link = cur.get("@odata.nextLink")
    if nxt_link not in (None, "", "None"):
        return None, what + ": more pages were not read (@odata.nextLink is set)"
    trunc = cur.get("paginationTruncated")
    if trunc is True or str(trunc).strip().lower() == "true":
        return None, what + ": the read was truncated at the page limit"
    for it in cur.get("value"):
        if not isinstance(it, dict):
            return None, what + ": an entry is not an object"
    return cur.get("value"), None


def strs(value):
    if not isinstance(value, list):
        return []
    return [str(v).strip() for v in value if v is not None and str(v).strip() not in ("", "None")]


def lowered(value):
    return [v.lower() for v in strs(value)]


#: Condition keys the check reads itself. Every other condition key with a value narrows the policy, so a
#: condition Microsoft adds later is read as narrowing (fail-closed), never as "every sign-in".
READ_CONDITIONS = ("users", "applications", "clientAppTypes", "locations", "platforms", "signInRiskLevels",
                   "userRiskLevels", "servicePrincipalRiskLevels")


def has_value(value):
    """True when some leaf inside value is set: an object or list whose fields are all empty is not a value
    (Graph returns unset conditions as null or as objects of empty lists)."""
    if value is None:
        return False
    if isinstance(value, dict):
        return any([has_value(v) for k, v in value.items() if not str(k).startswith("@")])
    if isinstance(value, list):
        return any([has_value(v) for v in value])
    return str(value).strip().lower() not in ("", "none", "null")


def narrowing(cond):
    """The conditions that narrow a policy below 'every sign-in', as short labels."""
    out = []
    locs = cond.get("locations")
    if isinstance(locs, dict):
        inc = lowered(locs.get("includeLocations"))
        exc = lowered(locs.get("excludeLocations"))
        # AllTrusted is the block's trusted exemption; any other exclusion is location_unread(), not narrowing
        if inc and inc != ["all"]:
            out.append("locations")
    elif has_value(locs):
        out.append("locations")
    plats = cond.get("platforms")
    if isinstance(plats, dict):
        inc = lowered(plats.get("includePlatforms"))
        exc = strs(plats.get("excludePlatforms"))
        if (inc and inc != ["all"]) or exc:
            out.append("platforms")
    elif has_value(plats):
        out.append("platforms")
    for k in sorted(cond.keys()):
        if k in READ_CONDITIONS or str(k).startswith("@"):
            continue
        if has_value(cond.get(k)):
            out.append(str(k)[:40])
    return out


#: Every client app type Conditional Access knows: modern (browser, desktop and mobile apps) and legacy
#: (Exchange ActiveSync and other basic-auth clients such as IMAP, POP, SMTP AUTH and ROPC).
CLIENT_APP_TYPES = ("browser", "mobileappsanddesktopclients", "exchangeactivesync", "other")


def all_client_apps(cond):
    types = lowered(cond.get("clientAppTypes"))
    if len(types) == 0 or "all" in types:
        return True
    for t in CLIENT_APP_TYPES:
        if t not in types:
            return False
    return True


def account_ref(uid):
    """A partial object id for reasons: enough to find the account in Entra, no personal data (C4)."""
    return "user " + str(uid)[:8] + "..."


def is_true(value):
    return value is True or str(value).strip().lower() == "true"


def object_ids(values):
    return set(v for v in lowered(values) if v not in ("all", "none", "guestsorexternalusers"))


def read_memberships(body):
    """{lower-case group id: set of member ids, or None when that list was not read whole}, paired by position."""
    holder = to_obj(body.get("caPolicyGroups"))
    ids = holder.get("groupIds") if isinstance(holder, dict) else None
    bodies = to_obj(body.get("groupMembers"))
    out = {}
    if not isinstance(ids, list) or not isinstance(bodies, list) or len(ids) != len(bodies):
        return out
    for index in range(len(ids)):
        entry = to_obj(ids[index])
        gid = str((entry.get("id") if isinstance(entry, dict) else entry) or "").strip().lower()
        if not gid:
            continue
        if gid in out:
            out[gid] = None
            continue
        items, why = graph_collection(bodies[index], "group members")
        if why or [i for i in items if not str(i.get("id") or "").strip()]:
            out[gid] = None
            continue
        out[gid] = set(str(i.get("id")).strip().lower() for i in items)
    return out


def read_accounts(items, cutoff):
    """({lower-case id: 'signal' or 'quiet'} for the enabled Member accounts, '' or a reason the read is unusable).
    'signal': a non-interactive sign-in after cutoff and no interactive one after cutoff (none ever counts). Timestamps compare as UTC strings."""
    out = {}
    carried = False
    for item in items:
        uid = str(item.get("id") or "").strip().lower()
        if not uid:
            return None, "a user entry carries no id"
        if not is_true(item.get("accountEnabled")) or str(item.get("userType") or "").strip().lower() != "member":
            continue
        activity = to_obj(item.get("signInActivity"))
        if "signInActivity" in item:
            carried = True
        stamps = []
        for field in ("lastSignInDateTime", "lastNonInteractiveSignInDateTime"):
            value = activity.get(field) if isinstance(activity, dict) else None
            text = str(value).strip() if value is not None else ""
            if text in ("", "None", "null"):
                stamps.append("")
            elif re.match(GRAPH_TIME, text):
                stamps.append(text[:19])
            else:
                return None, "a sign-in date is not a Graph UTC timestamp"
        interactive, background = stamps
        quiet_interactive = interactive == "" or interactive < cutoff
        out[uid] = "signal" if background != "" and background >= cutoff and quiet_interactive else "quiet"
    if out and not carried:
        return None, "the user read carries no signInActivity (it needs AuditLog.Read.All and Entra ID P1)"
    return out, ""


def requires_mfa(policy):
    controls = policy.get("grantControls")
    if not isinstance(controls, dict):
        return False
    strength = to_obj(controls.get("authenticationStrength"))
    return "mfa" in lowered(controls.get("builtInControls")) or (isinstance(strength, dict) and has_value(strength))


def enabled(policy):
    return str(policy.get("state") or "").strip().lower() == "enabled"


def users_of(policy):
    cond = policy.get("conditions") if isinstance(policy.get("conditions"), dict) else {}
    return cond.get("users") if isinstance(cond.get("users"), dict) else {}


# Directory Synchronization Accounts role template: the Entra Connect sync account holds it and cannot be blocked
# without breaking directory sync, so excluding that role alone does not make a block undecided.
DIRSYNC_ROLE = "d29b2b05-8046-44ba-8758-1e26182fcf32"
ALL_RISK_LEVELS = set(["high", "medium", "low", "none"])


def risk_only(cond):
    """True when the policy fires only for some risk levels (all four levels, 'none' included, is no narrowing)."""
    for risk in ("signInRiskLevels", "userRiskLevels", "servicePrincipalRiskLevels"):
        levels = set(lowered(cond.get(risk)))
        if levels and not ALL_RISK_LEVELS.issubset(levels):
            return True
    return False


def mfa_carve_outs(policies, memberships, accounts):
    """(accounts an enabled all-apps MFA policy would reach but excludes, the subset an All-users policy excludes by
    name or through a group of at most MAX_BREAK_GLASS members, '' or a reason the list is incomplete)."""
    carved = set()
    glass = set()
    why = ""
    for p in policies:
        cond = p.get("conditions") if isinstance(p.get("conditions"), dict) else {}
        apps = cond.get("applications") if isinstance(cond.get("applications"), dict) else {}
        if (not enabled(p) or not requires_mfa(p) or risk_only(cond)
                or "all" not in lowered(apps.get("includeApplications"))):
            continue
        users = users_of(p)
        everyone = "all" in lowered(users.get("includeUsers"))
        named = object_ids(users.get("includeUsers"))
        excluded = set(object_ids(users.get("excludeUsers")))
        small = set(excluded)
        for gid in object_ids(users.get("excludeGroups")):
            members = memberships.get(gid)
            if members is None:
                why = "a group excluded from an MFA policy was not read whole, so its members are not known"
                continue
            excluded = excluded | members
            if len(members) <= MAX_BREAK_GLASS:
                small = small | members
        for uid in sorted(excluded & accounts):
            reached = everyone or uid in named
            for gid in object_ids(users.get("includeGroups")):
                members = memberships.get(gid)
                if members is None:
                    why = "a group an MFA policy includes was not read whole, so its members are not known"
                elif uid in members:
                    reached = True
            if reached:
                carved.add(uid)
                if everyone and uid in small:
                    glass.add(uid)
    return carved, glass, why


def location_unread(cond):
    """True when a policy excludes any location but AllTrusted. Named locations are not read, so an excluded
    country or IP range may or may not leave the accounts free to sign in (same rule as entra_ca_mfa_coverage.py)."""
    locs = cond.get("locations")
    exc = [e for e in lowered(locs.get("excludeLocations")) if e != "none"] if isinstance(locs, dict) else []
    return bool(exc) and exc != ["alltrusted"]


def location_exempt(policy):
    """True when a block policy leaves trusted locations open (excludeLocations is exactly AllTrusted)."""
    cond = policy.get("conditions") if isinstance(policy.get("conditions"), dict) else {}
    locs = cond.get("locations")
    return isinstance(locs, dict) and lowered(locs.get("excludeLocations")) == ["alltrusted"]


def full_block(policy):
    """True when an enabled policy blocks every cloud app for every client type with no other narrowing (a risk-only
    firing included); None when it would but for an excluded location other than AllTrusted (named locations are not
    read); else False. One rule in three files: full_block_reach in entra_ca_mfa_coverage.py and ismfaenforcedforusers.py;
    test_mfa_members_outside_parity.py pins them together."""
    controls = policy.get("grantControls")
    if not enabled(policy) or not isinstance(controls, dict) or "block" not in lowered(controls.get("builtInControls")):
        return False
    cond = policy.get("conditions")
    if not isinstance(cond, dict) or risk_only(cond):
        return False
    apps = cond.get("applications") if isinstance(cond.get("applications"), dict) else {}
    if ("all" not in lowered(apps.get("includeApplications")) or strs(apps.get("excludeApplications"))
            or has_value(apps.get("applicationFilter"))):
        return False
    if not all_client_apps(cond) or narrowing(cond):
        return False
    return None if location_unread(cond) else True


def sync_holders(body):
    """Lower-case user ids holding the Directory Synchronization Accounts role from an optional roleAssignments
    read; None when the part is absent, not read whole, lists no holder of this role (a filtered read cannot tell),
    or a holder is not a user (a group's members are not read), so the exemption note stays."""
    if "roleAssignments" not in body:
        return None
    items, why = graph_collection(body.get("roleAssignments"), "role assignments")
    if why:
        return None
    out = set()
    for item in items:
        if not isinstance(item, dict):
            return None
        if str(item.get("roleDefinitionId") or item.get("roleTemplateId") or "").strip().lower() != DIRSYNC_ROLE:
            continue
        principal = item.get("principal") if isinstance(item.get("principal"), dict) else {}
        pid = str(item.get("principalId") or principal.get("id") or "").strip().lower()
        kind = str(principal.get("@odata.type") or "").strip().lower().rsplit(".", 1)[-1]
        if not pid or kind != "user":
            return None
        out.add(pid)
    return out or None


def sync_role_excluded(policy):
    return DIRSYNC_ROLE in lowered(users_of(policy).get("excludeRoles"))


def reached_by(uid, policy, memberships):
    """True when the policy includes the account (all users, by id, or through a group read whole) and no user or
    group exclusion read whole removes it. Unread groups never count as reaching, so the account is still judged."""
    users = users_of(policy)
    included = "all" in lowered(users.get("includeUsers")) or uid in object_ids(users.get("includeUsers"))
    for gid in object_ids(users.get("includeGroups")):
        included = included or uid in (memberships.get(gid) or set())
    excluded = uid in object_ids(users.get("excludeUsers"))
    for gid in object_ids(users.get("excludeGroups")):
        members = memberships.get(gid)
        excluded = excluded or members is None or uid in members
    return included and not excluded


def blocked(uid, decided, memberships):
    """True when some full block policy includes and does not exclude the account; None when one may (or a block
    that excludes a named location not read would reach it); else False. decided: (policy, full_block result) pairs
    whose result is not False."""
    maybe = False
    for p, certain in decided:
        users = users_of(p)
        included = "all" in lowered(users.get("includeUsers")) or uid in object_ids(users.get("includeUsers"))
        unsure = False
        for gid in object_ids(users.get("includeGroups")):
            members = memberships.get(gid)
            if members is None:
                unsure = True
            elif uid in members:
                included = True
        if not included and not unsure:
            continue
        if uid in object_ids(users.get("excludeUsers")):
            continue
        excluded = False
        for gid in object_ids(users.get("excludeGroups")):
            members = memberships.get(gid)
            if members is None:
                unsure = True
            elif uid in members:
                excluded = True
        if excluded:
            continue
        other_roles = [r for r in lowered(users.get("excludeRoles")) if r != DIRSYNC_ROLE]
        if other_roles or has_value(users.get("excludeGuestsOrExternalUsers")):
            unsure = True
        if included and not unsure and certain:
            return True
        maybe = True
    return None if maybe else False


def transform(input):
    # Reading input.get("data") marks this transform as new-format for Token-Service, which then hands it the
    # undrilled workflow result as {"data": <response>, "validation": ...}, so @odata.nextLink survives.
    validation = {"status": "unknown", "errors": [], "warnings": []}
    try:
        if isinstance(input, dict) and "validation" in input and "data" in input:
            if isinstance(input.get("validation"), dict):
                validation = input.get("validation")
            body = unwrap(input.get("data"))[0]
        else:
            body, validation = unwrap(input)
        if body is None:
            return not_measured(validation, "The response body is empty; nothing was read from Microsoft Entra ID.")
        why = envelope_error(body)
        if why:
            return not_measured(validation, "Microsoft Entra ID: " + why + ". This is a credential or permission "
                                "result, not a finding.")
        if not isinstance(body, dict) or not has_part(body):
            return not_measured(validation, "Microsoft Entra ID: the response is not the "
                                "getServiceAccountSignInEvidence workflow result.")
        if workflow_truncated(body, "conditionalAccessPolicies"):
            return not_measured(validation, "Microsoft Entra ID: a list was cut off at its page limit "
                                "(paginationTruncated), so the read is incomplete.")
        policies, why = graph_collection(body.get("conditionalAccessPolicies"), "Conditional Access policies")
        if why:
            return not_measured(validation, "Microsoft Entra ID " + why + ".", "The read needs Policy.Read.All, which "
                                "the existing Conditional Access checks already use.")
        if workflow_truncated(body, "signInUsers"):
            return not_measured(validation, "Microsoft Entra ID: the user list was cut off at its page limit "
                                "(paginationTruncated), so the read is incomplete.")
        items, why = graph_collection(body.get("signInUsers"), "users with sign-in activity")
        if why:
            return not_measured(validation, "Microsoft Entra ID " + why + ".", "The sign-in activity read needs "
                                "AuditLog.Read.All with admin consent and an Entra ID P1 or P2 licence.")
        cutoff = (datetime.now(timezone.utc) - timedelta(days=SIGNAL_DAYS)).isoformat()[:19]
        accounts, why = read_accounts(items, cutoff)
        if why:
            return not_measured(validation, "Microsoft Entra ID users with sign-in activity: " + why + ".")
        if not accounts:
            # Every tenant has enabled member accounts: an empty read proves nothing (fail closed).
            return not_measured(validation, "Microsoft Entra ID returned no enabled member account, so which accounts "
                                "are service accounts cannot be read.")
        memberships = read_memberships(body)
        carved, glass, carve_why = mfa_carve_outs(policies, memberships, set(accounts))
        by_signal = set(u for u in accounts if accounts[u] == "signal")
        carve_only = carved - by_signal
        break_glass = glass - by_signal
        service = by_signal | (carve_only - break_glass)
        holders = sync_holders(body)
        decided = [(p, full_block(p)) for p in policies]
        decided = [(p, d) for p, d in decided if d is not False]
        blocks = [p for p, d in decided if d]
        # A role holder is left out only when an enabled full block that reaches it excludes the role (the advised
        # exemption); any other holder is judged like every account.
        sync_held = set(u for u in (service & holders if holders else ())
                        if [p for p in blocks if sync_role_excluded(p) and reached_by(u, p, memberships)])
        service = service - sync_held
        unblocked = []
        undecided = []
        for uid in sorted(service):
            state = blocked(uid, decided, memberships)
            if state is False:
                unblocked.append(uid)
            elif state is None:
                undecided.append(uid)
        summary = {"policiesRead": len(policies), "enabledMemberAccounts": len(accounts),
                   "serviceAccountsBySignInSignal": len(by_signal), "serviceAccountsByMfaExclusion": len(carve_only - break_glass),
                   "breakGlassAccountsNotJudged": len(break_glass), "fullBlockPolicies": len(blocks),
                   "trustedLocationExemption": any(location_exempt(p) for p in blocks),
                   "syncRoleExempted": not sync_held and any(sync_role_excluded(p) for p in blocks),
                   "syncRoleHoldersNotJudged": len(sync_held),
                   "unblocked": len(unblocked), "undecided": len(undecided), "signalDays": SIGNAL_DAYS}
        scope = (f"service accounts are enabled member accounts with a non-interactive sign-in and no interactive one "
                 f"in {SIGNAL_DAYS} days, or that a Conditional Access MFA policy would reach but excludes")
        if break_glass:
            more = f"; more than the {MAX_BREAK_GLASS} expected, so a pass is not given" \
                if len(break_glass) > MAX_BREAK_GLASS else ""
            scope = scope + f" ({len(break_glass)} excluded account(s) treated as emergency access and not judged{more})"
        exempt_note = ""
        if [p for p in blocks if location_exempt(p)]:
            exempt_note = " (at least one blocks sign-in outside trusted locations)"
        if not sync_held and [p for p in blocks if sync_role_excluded(p)]:
            exempt_note += (" (holders of the Directory Synchronization Accounts role are excluded from a block and "
                            "were not checked)")
        elif sync_held:
            exempt_note += (f" ({len(sync_held)} holder(s) of the Directory Synchronization Accounts role excluded from "
                            "a block that reaches them were not judged)")
        if unblocked:
            shown = ", ".join(account_ref(u) for u in unblocked[:MAX_NAMED])
            if len(unblocked) > MAX_NAMED:
                shown = shown + " and " + str(len(unblocked) - MAX_NAMED) + " more"
            return create_response(
                result={KEY: False},
                validation=validation,
                fail_reasons=[str(len(unblocked)) + " of " + str(len(service)) + " service account(s) are not blocked "
                              "from interactive sign-in by an enabled Conditional Access policy that blocks all cloud "
                              "apps for every client type: " + shown + ". Scope: " + scope + "."],
                recommendations=["Move the workload to a service principal or managed identity, or restrict these "
                                 "accounts with a Conditional Access policy that blocks all cloud apps outside your "
                                 "trusted locations. Conditional Access also applies to non-interactive sign-ins, so a "
                                 "block with no location exemption stops a working workload. Exclude the Microsoft "
                                 "Entra Connect sync account from any such policy by excluding the Directory "
                                 "Synchronization Accounts role, not the account by name."],
                input_summary=summary,
            )
        if len(sync_held) > MAX_BREAK_GLASS:
            return not_measured(validation, "Microsoft Entra ID: " + str(len(sync_held)) + " service accounts hold the "
                                "Directory Synchronization Accounts role, more than the Entra Connect sync accounts "
                                "expected, so they are not judged and a pass is not given. Attest, or remove the role "
                                "from non-sync accounts.")
        if len(break_glass) > MAX_BREAK_GLASS:
            return not_measured(validation, "Microsoft Entra ID: " + str(len(break_glass)) + " accounts are excluded "
                                "from an all-users MFA policy by name or through a small group, more than the "
                                + str(MAX_BREAK_GLASS) + " emergency-access accounts expected, so they cannot be told "
                                "from service accounts. Attest, or exclude fewer accounts.")
        if undecided or carve_why:
            reason = carve_why or (str(len(undecided)) + " service account(s) are targeted by a block policy whose "
                                   "group membership, role, guest or named-location exclusion was not read, so whether it blocks them "
                                   "cannot be decided")
            return not_measured(validation, "Microsoft Entra ID: " + reason + ".", None, summary)
        if not service:
            return create_response(
                result={KEY: True},
                validation=validation,
                pass_reasons=[("Only holders of the Directory Synchronization Accounts role were found "
                               f"({len(sync_held)}), and an enabled block excludes that role, so none is judged. "
                               if sync_held else "No service account found: no enabled member account has a "
                               f"non-interactive sign-in and no interactive one in {SIGNAL_DAYS} days, and no "
                               "Conditional Access MFA policy excludes one (user list and sign-in activity read whole). ")
                              + "Scope: " + scope + "."],
                input_summary=summary,
            )
        return create_response(
            result={KEY: True},
            validation=validation,
            pass_reasons=["All " + str(len(service)) + " service account(s) are blocked from every cloud app by an "
                          "enabled Conditional Access block policy" + exempt_note + ". Scope: " + scope + "."],
            input_summary=summary,
        )
    except Exception as e:
        return not_measured(validation, "Transformation error: " + str(e)[:300])
