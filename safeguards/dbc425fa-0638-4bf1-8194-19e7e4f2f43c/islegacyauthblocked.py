"""
Transformation: isLegacyAuthBlocked
Vendor: Google Workspace  |  Category: Email Security

Criterion: legacy (password-only, "less secure app") sign-in is blocked for the whole organisation.
(isEquals true)

Data source: Cloud Identity Policy API, one GET (IS method getLessSecureAppsPolicies):
  GET https://cloudidentity.googleapis.com/v1beta1/policies
      ?filter=setting.type.matches('security.less_secure_apps')&pageSize=100
  scope https://www.googleapis.com/auth/cloud-identity.policies.readonly (domain-wide delegation).
Docs: https://cloud.google.com/identity/docs/concepts/supported-policy-api-settings
  Setting settings/security.less_secure_apps, field allowLessSecureApps (boolean).
  Default when the field is absent: allow_less_secure_apps = false (Policy API concepts, default field values).
Each policy carries policyQuery.orgUnit (required), optionally policyQuery.group, a CEL policyQuery.query and
an output-only decimal policyQuery.sortOrder; type SYSTEM (Google's default for the edition) or ADMIN (set by
an administrator). Where several policies target the same org unit (or group), the higher sortOrder wins.
Integration-Service hands scalars over as strings ("True", "False", "201.00183").

Rule, per target (org unit, or group within an org unit):
  * A policy that allows less secure apps is OVERRIDDEN only when a policy on the same target with a higher
    sortOrder sets them off and its query is the plain target clause (no licence or other condition), so it
    covers every user the allowing policy covers.
  * Any allowing policy that is not overridden is an org unit or group where less secure apps are allowed.

Verdict:
  True   the policy list is complete (no nextPageToken) and every less-secure-apps policy is off or
         overridden; or the list is a real, complete, non-empty policy list that covers security settings
         (at least one settings/security.* policy) and holds no less-secure-apps policy at all (Google's
         documented default: not allowed).
  False  at least one org unit or group allows less secure apps and nothing on that target overrides it.
  None   (Unevaluated, dataCollection error) error or scope body, None, {}, empty or unrelated JSON, a partial
         list (nextPageToken left or the read marked truncated), a policy record that is not a Policy API
         record, a less-secure-apps policy with no org unit (coverage cannot be read), or one whose value or
         precedence cannot be read on a target where no allowing policy was proven in force.

Does not prove: IMAP/POP enablement or app passwords, which this setting does not carry. Google ended
less-secure-app sign-in for Workspace accounts in 2024-2025; this reads the configured setting.
"""
import json
import re
from datetime import datetime

KEY = "isLegacyAuthBlocked"
SETTING = "security.less_secure_apps"
REQUIRED_SCOPE = "https://www.googleapis.com/auth/cloud-identity.policies.readonly"
META = {"transformationId": KEY, "vendor": "Google Workspace", "category": "Email Security"}
# Plain pattern strings, not re.compile: the Token-Service sandbox refuses any call named compile.
OU_ONLY = (r"^entity\.org_units\.exists\(org_unit, org_unit\.org_unit_id == orgUnitId\('[A-Za-z0-9_-]+'\)\)$")
GROUP_AND_OU = (r"^entity\.groups\.exists\(group, group\.group_id == groupId\('[A-Za-z0-9_-]+'\)\) && "
                          r"entity\.org_units\.exists\(org_unit, org_unit\.org_unit_id == orgUnitId\('[A-Za-z0-9_-]+'\)\)$")
SCOPE_HINTS = ["insufficient authentication scopes", "access_token_scope_insufficient", "unauthorized_client",
               "scope_not_granted", "access_denied", "request had insufficient authentication"]


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
    """allowLessSecureApps as True/False; absent field = documented default False; None when unreadable."""
    value = setting.get("value")
    if not isinstance(value, dict):
        return None
    camel = "allowLessSecureApps" in value
    snake = "allow_less_secure_apps" in value
    if not camel and not snake:
        return False
    first = as_bool(value.get("allowLessSecureApps")) if camel else None
    second = as_bool(value.get("allow_less_secure_apps")) if snake else None
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
    if data.get("paginationTruncated") is True or text(data.get("paginationTruncated")).lower() == "true":
        return None, "The policy read was truncated; a partial list is not evaluated."
    if text(data.get("nextPageToken")):
        return None, ("Google returned more pages (nextPageToken) that were not read; org unit coverage of the "
                      "less secure apps setting cannot be confirmed.")
    policies = data.get("policies")
    if not isinstance(policies, list):
        return None, "No policies list in the response: the less secure apps read cannot be shown to have run."
    if not policies:
        return None, ("The policy list is empty: an empty body cannot be told apart from a read that returned "
                      "nothing, so Google's default is not assumed.")
    for policy in policies:
        if not is_policy_record(policy):
            return None, "The response holds records that are not Cloud Identity policies; nothing is evaluated."
    return policies, None


def target_of(policy):
    query = policy.get("policyQuery") if isinstance(policy.get("policyQuery"), dict) else {}
    org_unit = text(query.get("orgUnit"))
    if not org_unit:
        return None
    return org_unit + "|" + text(query.get("group"))


def plain_target_query(policy):
    query = policy.get("policyQuery") if isinstance(policy.get("policyQuery"), dict) else {}
    q = text(query.get("query"))
    if text(query.get("group")):
        return bool(re.match(GROUP_AND_OU, q))
    return bool(re.match(OU_ONLY, q))


def label(target):
    parts = target.split("|")
    return ("group " + parts[1] + " in " + parts[0]) if parts[1] else parts[0]


def evaluate(policies):
    entries = []
    unreadable = 0
    unreadable_targets = []
    unplaced = 0
    for policy in policies:
        if not text(policy["setting"].get("type")).endswith(SETTING):
            continue
        target = target_of(policy)
        allowed = allowed_value(policy["setting"])
        query = policy.get("policyQuery") if isinstance(policy.get("policyQuery"), dict) else {}
        if target is None or allowed is None:
            unreadable = unreadable + 1
            if target is not None:
                unreadable_targets.append(target)
            else:
                unplaced = unplaced + 1
            continue
        entries.append({"target": target, "allowed": allowed, "order": as_order(query.get("sortOrder")),
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
        unclear = [p for p in later_off if p["order"] is None or entry["order"] is None
                   or (p["order"] > entry["order"] and not p["plain"])]
        if unclear or entry["target"] in unreadable_targets:
            uncertain.append(entry["target"])
        else:
            effective.append(entry["target"])
    return entries, unreadable, unplaced, effective, uncertain, overridden


def transform(input):
    try:
        if isinstance(input, (str, bytes)) and len(input.strip()) == 0:
            input = None
        if isinstance(input, bytes):
            input = input.decode("utf-8")
        if isinstance(input, str):
            input = json.loads(input)
        if input is None:
            return unevaluated("No response body; the less secure apps setting was not read.")
        data, validation = extract_input(input)
        problem = error_in(data)
        if problem:
            return unevaluated(explain_error(problem), validation)
        policies, problem = read_policies(data)
        if problem:
            return unevaluated(problem, validation)
        entries, unreadable, unplaced, effective, uncertain, overridden = evaluate(policies)
        targets = sorted(set([e["target"] for e in entries]))
        summary = {"policiesRead": len(policies), "lessSecureAppsPolicies": len(entries) + unreadable,
                   "targets": len(targets), "allowingTargets": len(set(effective)),
                   "overriddenAllowingPolicies": overridden, "uncertainAllowingPolicies": len(uncertain),
                   "unreadablePolicies": unreadable, "policiesWithoutOrgUnit": unplaced}
        result = {KEY: None, "lessSecureAppsPolicyCount": len(entries) + unreadable,
                  "lessSecureAppsAllowedTargetCount": len(set(effective))}
        if unplaced:
            return unevaluated(str(unplaced) + " less secure apps policy(ies) carry no org unit; any of them could "
                               "override another target, so org unit coverage cannot be read.", validation, summary)
        if effective:
            where = sorted(set(effective))
            result[KEY] = False
            return create_response(
                result=result, validation=validation, input_summary=summary,
                fail_reasons=["Less secure apps are allowed for " + str(len(where)) + " org unit(s) or group(s): "
                              + "; ".join([label(t) for t in where[:10]])
                              + (" (and " + str(len(where) - 10) + " more)" if len(where) > 10 else "")],
                recommendations=["In the Google Admin console, Security > Access and data control > Less secure "
                                 "apps, set 'Disable access to less secure apps' for the top-level org unit and "
                                 "remove every org unit or group override that allows them"])
        if uncertain or unreadable:
            return unevaluated(str(len(uncertain)) + " allowing policy(ies) with unreadable precedence and "
                               + str(unreadable) + " less secure apps policy(ies) with an unreadable org unit or "
                               "value; org unit coverage cannot be confirmed.", validation, summary)
        if not entries and not [p for p in policies if text(p["setting"].get("type")).startswith("settings/security.")]:
            return unevaluated("No less secure apps policy, and no other security setting either, in the "
                               + str(len(policies)) + " policies read: the list does not cover security settings, "
                               "so Google's default is not assumed.", validation, summary)
        result[KEY] = True
        if not entries:
            reason = ("No less secure apps policy in a complete list of " + str(len(policies)) + " Cloud Identity "
                      "policies: Google's documented default applies (less secure apps not allowed)")
        else:
            reason = ("Less secure apps are not allowed on any of " + str(len(targets)) + " org unit or group "
                      "target(s) (" + str(len(entries)) + " policies read, " + str(overridden)
                      + " allowing default(s) overridden by a later setting on the same target)")
        return create_response(result=result, validation=validation, input_summary=summary, pass_reasons=[reason])
    except Exception as e:
        return create_response(result={KEY: None}, transformation_errors=[str(e)],
                               api_errors=["Transformation error: " + str(e)],
                               fail_reasons=["Transformation error: " + str(e)])
