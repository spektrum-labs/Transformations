"""
Transformation: areServiceAccountsInteractiveSignInBlocked
Vendor: Microsoft Entra ID (One-Click)  |  Category: Identity and Access Management
Claim (IAM-001): service accounts cannot sign in interactively. In Entra ID that is a Conditional Access policy that
blocks the service-account group from every cloud app.
Source: a new workflow getServiceAccountSignInEvidence merging two EXISTING methods (no new permission):
    conditionalAccessPolicies  getConditionalAccessPolicies  GET /v1.0/identity/conditionalAccess/policies
    groups                     getGroupsMembershipRules      GET /v1.0/groups?$select=id,displayName,...&$top=999
Both are link-paginated by Integration-Service; an unread @odata.nextLink left in a part marks it truncated.

Service-account groups are the groups whose displayName names them as service accounts, in whole words: svc, svcs,
serviceaccount(s), "service account(s)", "non-interactive", "nonhuman" / "non-human". Microsoft Graph has no flag
for a service account, so the group name is the only signal; the reasons name every group read as one.
A group is BLOCKED when at least one enabled policy (state enabled, not report-only):
    - has grant control block,
    - targets all cloud apps (includeApplications All, no excluded apps),
    - includes the group (includeGroups) or All users, and does not exclude the group,
    - applies to every client app type (none listed, or "all", or both browser and mobileAppsAndDesktopClients),
    - and is not narrowed by locations, platforms, device filters or risk levels (a block "except from trusted
      locations" still lets the accounts sign in interactively from there, so it does not count).
True: every service-account group is blocked. False: at least one is not; the reason names it and any narrowed or
report-only policy that targets it. Membership is not expanded: a service account outside these groups is not seen.
Not evaluated (None with a dataCollection error): an empty, error or unrecognised body; either part missing, in
error, or truncated (an unread @odata.nextLink or paginationTruncated); or no group named as a service-account group.
"""
import json
import re
from datetime import datetime, timezone

KEY = "areServiceAccountsInteractiveSignInBlocked"

#: The criterion this file answers. None means "not measured", never "failed".
NONE_MEANS_NOT_EVALUATED = (KEY,)

WRAPPERS = ("apiResponse", "api_response", "response", "result", "Output", "rawResponse")

PARTS = ("conditionalAccessPolicies", "groups")

#: Whole words of a group name that mark it as a service-account group.
SINGLE_MARKERS = ("svc", "svcs", "serviceaccount", "serviceaccounts", "nonhuman", "noninteractive")
#: Adjacent word pairs that mark it ("Service Accounts", "non-interactive", "non-human").
PAIR_MARKERS = (("service", "account"), ("service", "accounts"), ("non", "interactive"), ("non", "human"))

MAX_NAMED = 20


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


def name_list(items):
    shown = ", ".join(items[:MAX_NAMED])
    if len(items) > MAX_NAMED:
        shown = shown + " and " + str(len(items) - MAX_NAMED) + " more"
    return shown


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


def is_service_group(name):
    words = [w for w in re.split(r"[^a-z0-9]+", str(name or "").lower()) if w]
    for w in words:
        if w in SINGLE_MARKERS:
            return True
    for i in range(len(words) - 1):
        for a, b in PAIR_MARKERS:
            if words[i] == a and words[i + 1] == b:
                return True
    return False


def strs(value):
    if not isinstance(value, list):
        return []
    return [str(v).strip() for v in value if v is not None and str(v).strip() not in ("", "None")]


def lowered(value):
    return [v.lower() for v in strs(value)]


def narrowing(cond):
    """The conditions that narrow a policy below 'every sign-in', as short labels."""
    out = []
    locs = cond.get("locations")
    if isinstance(locs, dict):
        inc = lowered(locs.get("includeLocations"))
        exc = strs(locs.get("excludeLocations"))
        if (inc and inc != ["all"]) or exc:
            out.append("locations")
    plats = cond.get("platforms")
    if isinstance(plats, dict):
        inc = lowered(plats.get("includePlatforms"))
        exc = strs(plats.get("excludePlatforms"))
        if (inc and inc != ["all"]) or exc:
            out.append("platforms")
    devs = cond.get("devices")
    if isinstance(devs, dict) and (isinstance(devs.get("deviceFilter"), dict) or strs(devs.get("excludeDevices"))
                                   or strs(devs.get("includeDevices"))):
        out.append("devices")
    for k in ("signInRiskLevels", "userRiskLevels", "servicePrincipalRiskLevels"):
        if strs(cond.get(k)):
            out.append(k)
    if isinstance(cond.get("authenticationFlows"), dict):
        out.append("authenticationFlows")
    return out


def all_client_apps(cond):
    types = lowered(cond.get("clientAppTypes"))
    if len(types) == 0 or "all" in types:
        return True
    return "browser" in types and "mobileappsanddesktopclients" in types


def policy_reach(policy, group_id):
    """'blocks', 'narrowed:<why>', 'reportonly', 'excluded' or None when the policy does not target the group."""
    controls = policy.get("grantControls")
    if not isinstance(controls, dict) or "block" not in lowered(controls.get("builtInControls")):
        return None
    cond = policy.get("conditions")
    if not isinstance(cond, dict):
        return None
    users = cond.get("users") if isinstance(cond.get("users"), dict) else {}
    gid = group_id.lower()
    targets = gid in lowered(users.get("includeGroups")) or "all" in lowered(users.get("includeUsers"))
    if not targets:
        return None
    if gid in lowered(users.get("excludeGroups")):
        return "excluded"
    state = str(policy.get("state") or "").strip()
    if state.lower() != "enabled":
        return "reportonly" if state else "narrowed:no state"
    apps = cond.get("applications") if isinstance(cond.get("applications"), dict) else {}
    why = []
    if "all" not in lowered(apps.get("includeApplications")) or strs(apps.get("excludeApplications")):
        why.append("not all cloud apps")
    if not all_client_apps(cond):
        why.append("not every client app type")
    why = why + narrowing(cond)
    if why:
        return "narrowed:" + "/".join(why)
    return "blocks"


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
        policies, why = graph_collection(body.get("conditionalAccessPolicies"), "Conditional Access policies")
        if why:
            return not_measured(validation, "Microsoft Entra ID " + why + ".", "The read needs Policy.Read.All, which "
                                "the existing Conditional Access checks already use.")
        groups, why = graph_collection(body.get("groups"), "groups")
        if why:
            return not_measured(validation, "Microsoft Entra ID " + why + ".")
        service = []
        for g in groups:
            gid = str(g.get("id") or "").strip()
            if gid and is_service_group(g.get("displayName")):
                service.append((gid, str(g.get("displayName"))[:80]))
        summary = {"policiesRead": len(policies), "groupsRead": len(groups),
                   "serviceAccountGroups": [n for i, n in service][:MAX_NAMED]}
        if len(service) == 0:
            return not_measured(validation, "No Entra ID group is named as a service-account group (svc, Service "
                                "Accounts, non-interactive) among " + str(len(groups)) + " groups, so which accounts "
                                "are service accounts cannot be read.",
                                "Put service accounts in a group whose name says so (for example 'SG-Service-Accounts') "
                                "and block it from all cloud apps with Conditional Access, or provide the evidence as a "
                                "document.", summary)
        blocked = []
        unblocked = []
        for gid, gname in service:
            reach = []
            for p in policies:
                r = policy_reach(p, gid)
                if r is not None:
                    reach.append((str(p.get("displayName") or p.get("id") or "policy")[:60], r))
            blocking = [n for n, r in reach if r == "blocks"]
            if blocking:
                blocked.append(gname + " (by '" + blocking[0] + "')")
                continue
            notes = [n + ": " + r.replace("narrowed:", "narrowed by ").replace("reportonly", "report-only").replace(
                "excluded", "excludes the group") for n, r in reach]
            unblocked.append(gname + (" [" + "; ".join(notes[:3]) + "]" if notes else " [no blocking policy targets it]"))
        summary["blockedGroups"] = blocked[:MAX_NAMED]
        summary["unblockedGroups"] = unblocked[:MAX_NAMED]
        if unblocked:
            return create_response(
                result={KEY: False},
                validation=validation,
                fail_reasons=[str(len(unblocked)) + " of " + str(len(service)) + " Entra ID service-account group(s) "
                              "are not blocked from interactive sign-in by an enabled Conditional Access policy that "
                              "blocks all cloud apps for every client type: " + name_list(unblocked)],
                recommendations=["Create (or enable) a Conditional Access policy that includes each group named, targets "
                                 "All cloud apps, applies to all client app types, has no location or platform "
                                 "exception, and grants Block access."],
                input_summary=summary,
            )
        return create_response(
            result={KEY: True},
            validation=validation,
            pass_reasons=["All " + str(len(service)) + " Entra ID service-account group(s) are blocked from every cloud "
                          "app by an enabled Conditional Access block policy: " + name_list(blocked) +
                          ". Scope: members of these groups; accounts outside them are not seen."],
            input_summary=summary,
        )
    except Exception as e:
        return not_measured(validation, "Transformation error: " + str(e)[:300])
