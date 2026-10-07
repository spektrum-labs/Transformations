"""
Transformation: isAutoForwardDisabled
Vendor: Google Workspace  |  Category: Email Security

Criterion: users cannot automatically forward their mail to outside addresses, for the whole organisation.
(isEquals true)

Data source: Cloud Identity Policy API, one paginated GET (IS method getGmailPolicies):
  GET https://cloudidentity.googleapis.com/v1beta1/policies
      ?filter=setting.type.matches('gmail.*')&pageSize=100
  scope https://www.googleapis.com/auth/cloud-identity.policies.readonly (domain-wide delegation; the same
  scope the other Gmail checks already use).
Docs: https://cloud.google.com/identity/docs/concepts/supported-policy-api-settings
  Setting settings/gmail.auto_forwarding, field enable_auto_forwarding (boolean), Admin console caption
  "Allow users to automatically forward incoming email to another address".
  Default (Policy API concepts, default field values): enable_auto_forwarding = true. Google usually returns
  a SYSTEM policy for this setting, but not on every tenant. A complete Gmail list without any
  auto_forwarding policy therefore cannot be told apart from a read that left the setting out, and is not
  evaluated (no default is assumed in either direction).
The Gmail setting covers every forwarding address, internal and external; turned off, it blocks external
forwarding too, so it is a stricter control than "external only" and proves the criterion.

Each policy carries policyQuery.orgUnit, optionally policyQuery.group, a CEL policyQuery.query and an
output-only decimal policyQuery.sortOrder; type SYSTEM (Google's default) or ADMIN (set by an administrator).
Where several policies target the same org unit (or group), the higher sortOrder wins. Child org units
without their own policy inherit from their parent. Integration-Service hands scalars over as strings
("True", "False", "201.00183").

Org unit overrides:
  * An allowing policy on any org unit or group is in force unless a policy on the same target with a higher
    sortOrder turns forwarding off and has the plain target query (no licence or other condition) naming
    that same org unit (and group). A conditional later "off" leaves the allowing policy in force for every
    user outside its condition, so the target still allows forwarding.
  * The top-level org unit must itself have a plain disabling policy in force. The top-level org unit is the org
    unit that carries Google's SYSTEM policies in the same list (Google attaches defaults to the root).

Verdict:
  True   the list is complete, the top-level org unit has a plain disabling policy in force, and no org unit
         or group has an allowing policy in force.
  False  an org unit or group allows automatic forwarding and nothing on that target overrides it.
  None   (Unevaluated, dataCollection error) error or scope body, None, {}, empty or unrelated JSON, a partial
         list (nextPageToken or a truncation marker on any wrapper level, or in paginationStats), records
         that are not Policy API records, a complete Gmail list with no auto_forwarding policy at all, a
         list with no Gmail setting at all (the read cannot be shown to cover Gmail), a top-level org unit
         that cannot be identified, or an auto-forwarding policy whose org unit, value or precedence cannot be
         read where it decides the verdict.

Does not prove: forwarding a user set up before the setting was turned off, or admin routing and compliance
rules that forward mail, which this setting does not carry.
"""
import json
import re
from datetime import datetime

KEY = "isAutoForwardDisabled"
SETTING = "gmail.auto_forwarding"
REQUIRED_SCOPE = "https://www.googleapis.com/auth/cloud-identity.policies.readonly"
META = {"transformationId": KEY, "vendor": "Google Workspace", "category": "Email Security"}
# Plain pattern strings, not re.compile: the Token-Service sandbox refuses any call named compile.
OU_ONLY = (r"^entity\.org_units\.exists\(org_unit, org_unit\.org_unit_id == orgUnitId\('([A-Za-z0-9_-]+)'\)\)$")
GROUP_AND_OU = (r"^entity\.groups\.exists\(group, group\.group_id == groupId\('([A-Za-z0-9_-]+)'\)\) && "
                r"entity\.org_units\.exists\(org_unit, org_unit\.org_unit_id == orgUnitId\('([A-Za-z0-9_-]+)'\)\)$")
MARKER_KEYS = ["paginationStats", "iterateStats"]
SCOPE_HINTS = ["insufficient authentication scopes", "access_token_scope_insufficient", "unauthorized_client",
               "scope_not_granted", "access_denied", "request had insufficient authentication"]
RECOMMENDATION = ("In the Google Admin console, Apps > Google Workspace > Gmail > End User Access, turn off "
                  "'Allow users to automatically forward incoming email to another address' for the top-level "
                  "org unit and remove every org unit or group override that turns it back on")


def truthy(value):
    return value is True or text(value).lower() == "true"


def stats_truncated(stats, depth):
    """paginationStats / iterateStats: True when any level reports a truncated or incomplete read."""
    if depth > 4 or not isinstance(stats, dict):
        return False
    if truthy(stats.get("paginationTruncated")) or truthy(stats.get("truncated")) or truthy(stats.get("isTruncated")):
        return True
    if text(stats.get("nextPageToken")) or stats.get("complete") is False or text(stats.get("complete")).lower() == "false":
        return True
    for value in stats.values():
        if stats_truncated(value, depth + 1):
            return True
    return False


def level_truncated(level):
    """A partial-read marker on this wrapper level (nextPageToken, paginationTruncated, stats blocks)."""
    if not isinstance(level, dict):
        return False
    if truthy(level.get("paginationTruncated")) or text(level.get("nextPageToken")):
        return True
    for key in MARKER_KEYS:
        if stats_truncated(level.get(key), 0):
            return True
    return False


def any_level_truncated(input_data):
    """A partial-read marker on any wrapper level, following every wrapper key (not only the first)."""
    levels = [input_data]
    for attempt in range(6):
        following = []
        for level in levels:
            if not isinstance(level, dict):
                continue
            if level_truncated(level):
                return True
            for key in ["data", "api_response", "response", "result", "apiResponse", "Output", "_response_data"]:
                if isinstance(level.get(key), dict):
                    following.append(level[key])
        if not following:
            return False
        levels = following[:50]
    return False


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output", "_response_data"]
        for attempt in range(4):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict) and "policies" not in data:
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped or not isinstance(data, dict):
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format - no schema validation performed"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None, recommendations=None,
                    input_summary=None, api_errors=None, transformation_errors=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    metadata = {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "2.0"}
    metadata.update(META)
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []),
                           "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success",
                               "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                           "recommendations": recommendations or [], "additionalFindings": []},
            "metadata": metadata,
        },
    }


def unevaluated(problem, validation=None, summary=None):
    return create_response(result={KEY: None}, validation=validation, fail_reasons=[problem], api_errors=[problem],
                           input_summary=summary)


def text(value):
    if value is None:
        return ""
    return str(value).strip()


def error_in(data):
    """Google's or Integration-Service's error text when the body is an error envelope, else ''."""
    if not isinstance(data, dict):
        return ""
    for key in ["error", "errors", "errorMessage", "errorCode", "vendorAuthError"]:
        value = data.get(key)
        if value:
            if isinstance(value, dict):
                return " ".join([text(value.get(k)) for k in ["code", "status", "message"] if value.get(k)]) or text(value)[:200]
            return (text(value) + " " + text(data.get("message"))).strip()[:300]
    for key in ["statusCode", "status_code"]:
        code = data.get(key)
        if code is not None and text(code) != "200":
            return "HTTP " + text(code) + " " + text(data.get("message"))
    if text(data.get("status")).lower() == "error":
        return text(data.get("message")) or "Integration error"
    return ""


def explain_error(problem):
    low = problem.lower()
    for hint in SCOPE_HINTS:
        if hint in low:
            return ("Scope not granted: add " + REQUIRED_SCOPE + " to Spektrum's domain-wide delegation grant in the "
                    "Google Admin console. Google said: " + problem[:240])
    return "Google returned an error: " + problem[:300]


def as_bool(value):
    """True/False from a bool or the strings IS sends ("True"/"False"); None when unreadable."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in ["true", "false"]:
        return value.strip().lower() == "true"
    return None


def as_order(value):
    if isinstance(value, bool) or value is None:
        return None
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def allowed_value(setting):
    """enableAutoForwarding as True/False; None when absent or unreadable. An absent field is not read as
    Google's default: a serializer that drops false-valued fields would make an empty value mean off."""
    value = setting.get("value")
    if not isinstance(value, dict):
        return None
    camel = "enableAutoForwarding" in value
    snake = "enable_auto_forwarding" in value
    if not camel and not snake:
        return None
    first = as_bool(value.get("enableAutoForwarding")) if camel else None
    second = as_bool(value.get("enable_auto_forwarding")) if snake else None
    if camel and first is None:
        return None
    if snake and second is None:
        return None
    if camel and snake and first != second:
        return None
    return first if camel else second


def is_policy_record(policy):
    if not isinstance(policy, dict):
        return False
    setting = policy.get("setting")
    return isinstance(setting, dict) and text(setting.get("type")).startswith("settings/")


def read_policies(data):
    """(policies, problem): the complete Policy API list, or the reason it is not one."""
    if not isinstance(data, dict):
        return None, "The response is not a Cloud Identity Policy API list; nothing to evaluate."
    if level_truncated(data):
        return None, ("The policy read was partial (nextPageToken or a truncation marker); org unit coverage of "
                      "the automatic forwarding setting cannot be confirmed.")
    policies = data.get("policies")
    if not isinstance(policies, list):
        return None, "No policies list in the response: the Gmail settings read cannot be shown to have run."
    if not policies:
        return None, ("The policy list is empty: an empty body cannot be told apart from a read that returned "
                      "nothing, so no verdict is drawn.")
    for policy in policies:
        if not is_policy_record(policy):
            return None, "The response holds records that are not Cloud Identity policies; nothing is evaluated."
    return policies, None


def query_of(policy):
    return policy.get("policyQuery") if isinstance(policy.get("policyQuery"), dict) else {}


def target_of(policy):
    query = query_of(policy)
    org_unit = text(query.get("orgUnit"))
    if not org_unit:
        return None
    return org_unit + "|" + text(query.get("group"))


def last_part(name):
    return text(name).split("/")[-1]


def plain_target_query(policy):
    """True when the CEL query is the bare target clause AND names the same org unit (and group)."""
    query = query_of(policy)
    q = text(query.get("query"))
    if text(query.get("group")):
        found = re.match(GROUP_AND_OU, q)
        return bool(found) and found.group(1) == last_part(query.get("group")) \
            and found.group(2) == last_part(query.get("orgUnit"))
    found = re.match(OU_ONLY, q)
    return bool(found) and found.group(1) == last_part(query.get("orgUnit"))


def label(target):
    parts = target.split("|")
    return ("group " + parts[1] + " in " + parts[0]) if parts[1] else parts[0]


def root_org_unit(policies):
    """The top-level org unit: the single org unit that carries Google's SYSTEM (default) policies."""
    units = set()
    for policy in policies:
        if text(policy.get("type")).upper() != "SYSTEM":
            continue
        query = query_of(policy)
        if text(query.get("group")):
            continue
        if text(query.get("orgUnit")):
            units.add(text(query.get("orgUnit")))
    if len(units) == 1:
        return list(units)[0]
    return None


def evaluate(policies, root):
    entries = []
    unreadable_targets = []
    unplaced = 0
    for policy in policies:
        if not text(policy["setting"].get("type")).endswith(SETTING):
            continue
        target = target_of(policy)
        allowed = allowed_value(policy["setting"])
        if target is None:
            unplaced = unplaced + 1
            continue
        if allowed is None:
            unreadable_targets.append(target)
            continue
        entries.append({"target": target, "allowed": allowed, "order": as_order(query_of(policy).get("sortOrder")),
                        "plain": plain_target_query(policy), "type": text(policy.get("type")).upper()})
    effective = []
    uncertain = []
    overridden = 0
    for entry in entries:
        if not entry["allowed"]:
            continue
        peers = [p for p in entries if p is not entry and p["target"] == entry["target"]]
        later_off = [p for p in peers if not p["allowed"]]
        covered = [p for p in later_off if p["plain"] and p["order"] is not None and entry["order"] is not None
                   and p["order"] > entry["order"]]
        if covered:
            overridden = overridden + 1
            continue
        # A conditional later "off" only covers users inside its condition; the allowing policy stays in force
        # for everyone else, so it is not unclear. Only a missing sortOrder leaves precedence unknown.
        unclear = [p for p in later_off if p["order"] is None or entry["order"] is None]
        if unclear or entry["target"] in unreadable_targets:
            uncertain.append(entry["target"])
        else:
            effective.append(entry["target"])
    root_target = (root + "|") if root else None
    root_off = [e for e in entries if e["target"] == root_target and not e["allowed"]]
    root_plain_off = [e for e in root_off if e["plain"] and e["order"] is not None]
    if root_target is None:
        root_state = "unknown"
    elif root_target in uncertain or root_target in unreadable_targets:
        root_state = "unclear"
    elif root_plain_off:
        root_state = "off"
    elif root_off:
        root_state = "unclear"
    else:
        root_state = "default"
    return {"entries": entries, "unreadable": len(unreadable_targets), "unplaced": unplaced,
            "effective": effective, "uncertain": uncertain, "overridden": overridden, "root": root_state}


def transform(input):
    try:
        if isinstance(input, (str, bytes)) and len(input.strip()) == 0:
            input = None
        if isinstance(input, bytes):
            input = input.decode("utf-8")
        if isinstance(input, str):
            input = json.loads(input)
        if input is None:
            return unevaluated("No response body; the Gmail automatic forwarding setting was not read.")
        data, validation = extract_input(input)
        problem = error_in(data)
        if problem:
            return unevaluated(explain_error(problem), validation)
        if any_level_truncated(input):
            return unevaluated("The policy read was partial (nextPageToken or a truncation marker on a wrapper "
                               "level); org unit coverage cannot be confirmed.", validation)
        policies, problem = read_policies(data)
        if problem:
            return unevaluated(problem, validation)
        gmail = [p for p in policies if text(p["setting"].get("type")).startswith("settings/gmail.")]
        if not gmail:
            return unevaluated("No Gmail setting in the " + str(len(policies)) + " policies read: the list does "
                               "not cover Gmail settings, so the automatic forwarding setting cannot be judged.",
                               validation)
        root = root_org_unit(policies)
        state = evaluate(policies, root)
        entries = state["entries"]
        targets = sorted(set([e["target"] for e in entries]))
        summary = {"policiesRead": len(policies), "gmailPolicies": len(gmail),
                   "autoForwardingPolicies": len(entries) + state["unreadable"] + state["unplaced"],
                   "targets": len(targets), "allowingTargets": len(set(state["effective"])),
                   "overriddenAllowingPolicies": state["overridden"],
                   "uncertainAllowingPolicies": len(state["uncertain"]),
                   "unreadablePolicies": state["unreadable"], "policiesWithoutOrgUnit": state["unplaced"],
                   "topLevelOrgUnitState": state["root"]}
        result = {KEY: None, "autoForwardingPolicyCount": summary["autoForwardingPolicies"],
                  "autoForwardingAllowedTargetCount": len(set(state["effective"]))}
        if state["unplaced"]:
            return unevaluated(str(state["unplaced"]) + " automatic forwarding policy(ies) carry no org unit; "
                               "org unit coverage cannot be read.", validation, summary)
        if state["effective"]:
            where = sorted(set(state["effective"]))
            result[KEY] = False
            return create_response(
                result=result, validation=validation, input_summary=summary,
                fail_reasons=["Automatic forwarding is allowed for " + str(len(where)) + " org unit(s) or group(s): "
                              + "; ".join([label(t) for t in where[:10]])
                              + (" (and " + str(len(where) - 10) + " more)" if len(where) > 10 else "")],
                recommendations=[RECOMMENDATION])
        if state["root"] == "unknown":
            return unevaluated("The top-level org unit cannot be identified (no single org unit carries Google's "
                               "default policies), so organisation-wide coverage cannot be confirmed.",
                               validation, summary)
        if state["root"] == "unclear" or state["uncertain"] or state["unreadable"]:
            return unevaluated(str(len(state["uncertain"])) + " allowing policy(ies) with unreadable precedence, "
                               + str(state["unreadable"]) + " automatic forwarding policy(ies) with an unreadable "
                               "value, or a conditional top-level setting; organisation-wide coverage cannot be "
                               "confirmed.", validation, summary)
        if state["root"] == "default":
            if not entries:
                return unevaluated("No gmail.auto_forwarding policy in a complete list of " + str(len(gmail))
                                   + " Gmail policies: the setting was not returned, so whether automatic "
                                   "forwarding is allowed cannot be read. Setting it explicitly in the Admin "
                                   "console makes Google return it.", validation, summary)
            return unevaluated("No automatic forwarding policy applies to the top-level org unit ("
                               + str(len(entries)) + " policies on other targets): organisation-wide coverage "
                               "cannot be confirmed.", validation, summary)
        result[KEY] = True
        return create_response(
            result=result, validation=validation, input_summary=summary,
            pass_reasons=["Automatic forwarding is turned off for the top-level org unit and no org unit or group "
                          "turns it back on (" + str(len(entries)) + " automatic forwarding policies on "
                          + str(len(targets)) + " target(s), " + str(state["overridden"])
                          + " allowing setting(s) overridden by a later setting on the same target)"])
    except Exception as e:
        return create_response(result={KEY: None}, transformation_errors=[str(e)],
                               api_errors=["Transformation error: " + str(e)],
                               fail_reasons=["Transformation error: " + str(e)])
