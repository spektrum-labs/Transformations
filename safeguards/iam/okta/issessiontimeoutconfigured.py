# issessiontimeoutconfigured.py - Okta (Identity Engine and Classic)
#
# Method: workflow getMfaPolicyRules (Integration-Service), the same four GETs isconditionalaccessenabled.py reads;
# this transform uses the first two:
#   GET /api/v1/policies?type=OKTA_SIGN_ON        -> signOnPolicies   (global session policies)
#   GET /api/v1/policies/{policyId}/rules         -> signOnRules      (one list per policy, same order)
# Docs: https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Policy/
#   listPolicies, listPolicyRules (apiToken, or OAuth scope okta.policies.read; GA). Rule schema
#   OktaSignOnPolicyRule.actions.signon.{access, session.{maxSessionIdleMinutes, maxSessionLifetimeMinutes,
#   usePersistentCookie}}. maxSessionLifetimeMinutes: "Maximum number of minutes (from when the user signs in)
#   that a user's session is active ... Disable by setting to 0" (default 0, i.e. no maximum lifetime).
#   Integration-Service returns these values as strings ("240", "0", "False"); both forms are read.

KEY = "isSessionTimeoutConfigured"
UNLIMITED = "unlimited"


def transform(input):
    """
    isSessionTimeoutConfigured - the longest Okta global session LIFETIME, in minutes, that any active sign-in
    rule allows. The requirement's threshold decides (for example lessThan 10080 = at most 7 days).

    How the number is derived:
      * Only ACTIVE global session (OKTA_SIGN_ON) policies, and only their ACTIVE rules whose action is ALLOW
        (a DENY rule starts no session).
      * Each such rule's actions.signon.session.maxSessionLifetimeMinutes. 0 means Okta enforces no maximum
        lifetime.
      * Worst case: the LARGEST lifetime is reported, because any user who lands on that rule gets it. Rule and
        policy reachability (group assignment, priority shadowing) is not read, so a shadowed rule still counts.
      * When any judged rule has no maximum lifetime the value is the string "unlimited". That is a measurement,
        not a gap: a numeric threshold cannot be met by it, so the check reads Failed. It is never 0 or false,
        which a numeric comparison would read as 0 minutes and pass.

    Output: isSessionTimeoutConfigured (minutes, or "unlimited"), maxSessionLifetimeMinutes, maxSessionIdleMinutes
    (largest idle timeout among the same rules), allowRuleCount, policiesJudged.

    Unevaluated (value None, dataCollection status "error") on: an error body, missing policy or rule lists, rule
    lists that do not line up with the policies, no active global session policy, no active ALLOW rule, an ALLOW
    rule without session settings, or a lifetime that is not a whole number of minutes.

    Does not prove: which groups each policy applies to, app-level re-authentication (authentication policy
    reauthenticateIn), or the separate 24-hour administrator limit some requirements describe.
    """
    try:
        state = evaluate(input)
    except Exception as e:
        return unevaluated("Transformation error: " + str(e), [str(e)])
    if state["error"] is not None:
        return unevaluated(state["error"], [])
    worst = state["worst"]
    where = state["where"]
    summary = state["inputSummary"]
    if worst == UNLIMITED:
        fails = ["No maximum global session lifetime: " + str(len(where)) + " active ALLOW rule(s) set "
                 "maxSessionLifetimeMinutes to 0 (no limit)"]
        for item in where[:10]:
            fails.append("No lifetime limit: " + item)
        return respond(UNLIMITED, summary, [], fails,
                       ["Set a maximum Okta global session lifetime on every active ALLOW rule of every active "
                        "global session policy (Security > Global Session Policy > rule > Maximum Okta global "
                        "session lifetime)"])
    passes = ["Longest global session lifetime among " + str(summary["allowRuleCount"]) + " active ALLOW rule(s): "
              + str(worst) + " minutes (" + ", ".join(where[:3]) + ")"]
    return respond(worst, summary, passes, [], [])


def text(value):
    if value is None:
        return ""
    return str(value).strip()


def truthy(value):
    if isinstance(value, bool):
        return value
    return text(value).lower() == "true"


def as_dict(value):
    return value if isinstance(value, dict) else {}


def minutes(value):
    """A whole, non-negative number of minutes, or None when the value cannot be read as one."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, float):
        if value < 0 or value != int(value):
            return None
        return int(value)
    raw = text(value)
    if raw.isdigit():
        return int(raw)
    return None


def parse(value):
    import json
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    if isinstance(value, str):
        value = json.loads(value)
    for wrapper in ["data", "response", "result", "apiResponse", "_response_data"]:
        if isinstance(value, dict) and wrapper in value and "signOnPolicies" not in value and "accessPolicies" not in value:
            value = value[wrapper]
    return value


def error_in(data):
    if not isinstance(data, dict):
        return "Response is not an object with policy and rule lists"
    for k in ["errorCode", "errorSummary", "error", "errors", "errorMessage"]:
        if data.get(k):
            return "Okta returned an error: " + text(data.get(k))[:200]
    for k in ["statusCode", "status_code"]:
        if data.get(k) not in (None, 200, "200"):
            return "Okta returned HTTP " + text(data.get(k))
    return None


def rule_list(item):
    if isinstance(item, dict):
        for wrapper in ["apiResponse", "response", "result"]:
            if wrapper in item:
                return rule_list(item[wrapper])
        return None
    if isinstance(item, list):
        return [r for r in item if isinstance(r, dict)]
    return None


def pair(policies, rules):
    label = "Global session (OKTA_SIGN_ON)"
    if not isinstance(policies, list):
        return None, label + " policy list is missing"
    if not isinstance(rules, list) or len(rules) != len(policies):
        return None, label + " rule lists are missing or do not line up with the policies"
    out = []
    for index in range(len(policies)):
        policy = policies[index]
        if not isinstance(policy, dict):
            return None, label + " policy entry is not an object"
        found = rule_list(rules[index])
        if found is None:
            return None, label + " rules for policy '" + text(policy.get("name")) + "' are unreadable"
        out.append((policy, found))
    return out, None


def active(obj):
    return text(obj.get("status")).upper() == "ACTIVE"


def evaluate(raw):
    data = parse(raw)
    state = {"error": None, "worst": None, "where": [], "inputSummary": {}}
    problem = error_in(data)
    if problem is not None:
        state["error"] = problem
        return state
    pairs, problem = pair(data.get("signOnPolicies"), data.get("signOnRules"))
    if problem is not None:
        state["error"] = problem
        return state
    judged = [(p, r) for (p, r) in pairs if active(p)]
    if not judged:
        state["error"] = "No active global session (OKTA_SIGN_ON) policy was returned"
        return state
    lifetimes = []
    idles = []
    for policy, rules in judged:
        for rule in rules:
            if not active(rule):
                continue
            sign_on = as_dict(as_dict(rule.get("actions")).get("signon"))
            if text(sign_on.get("access")).upper() != "ALLOW":
                continue
            label = text(policy.get("name")) + " / " + text(rule.get("name"))
            session = sign_on.get("session")
            if not isinstance(session, dict):
                state["error"] = "ALLOW rule '" + label + "' carries no session settings"
                return state
            lifetime = minutes(session.get("maxSessionLifetimeMinutes"))
            if lifetime is None:
                state["error"] = ("ALLOW rule '" + label + "' has a session lifetime that is not a whole number of "
                                  "minutes: " + text(session.get("maxSessionLifetimeMinutes"))[:40])
                return state
            idle = minutes(session.get("maxSessionIdleMinutes"))
            if idle is not None:
                idles.append(idle)
            lifetimes.append((lifetime, label))
    if not lifetimes:
        state["error"] = "No active ALLOW rule in the active global session policies; no session is started to measure"
        return state
    unlimited = [label for (value, label) in lifetimes if value == 0]
    if unlimited:
        state["worst"] = UNLIMITED
        state["where"] = unlimited
    else:
        worst = max([value for (value, label) in lifetimes])
        state["worst"] = worst
        state["where"] = [label for (value, label) in lifetimes if value == worst]
    state["inputSummary"] = {
        "policiesJudged": len(judged),
        "allowRuleCount": len(lifetimes),
        "rulesWithoutLifetimeLimit": len(unlimited),
        "maxSessionLifetimeMinutes": state["worst"],
        "maxSessionIdleMinutes": max(idles) if idles else None,
    }
    return state


def metadata():
    from datetime import datetime
    return {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0",
            "transformationId": KEY, "vendor": "Okta", "category": "Identity"}


def respond(value, summary, passes, fails, recommendations):
    return {
        "transformedResponse": {KEY: value, "maxSessionLifetimeMinutes": value,
                                "maxSessionIdleMinutes": summary.get("maxSessionIdleMinutes"),
                                "allowRuleCount": summary.get("allowRuleCount"),
                                "policiesJudged": summary.get("policiesJudged")},
        "additionalInfo": {
            "dataCollection": {"status": "success", "errors": []},
            "validation": {"status": "success", "errors": [], "warnings": []},
            "transformation": {"status": "success", "errors": [], "inputSummary": summary},
            "evaluation": {"passReasons": passes, "failReasons": fails, "recommendations": recommendations,
                           "additionalFindings": []},
            "metadata": metadata(),
        },
    }


def unevaluated(reason, errors):
    return {
        "transformedResponse": {KEY: None, "maxSessionLifetimeMinutes": None},
        "additionalInfo": {
            "dataCollection": {"status": "error", "errors": [reason]},
            "validation": {"status": "error" if errors else "unknown", "errors": [], "warnings": []},
            "transformation": {"status": "error" if errors else "success", "errors": errors, "inputSummary": {}},
            "evaluation": {"passReasons": [], "failReasons": [reason], "recommendations": [], "additionalFindings": []},
            "metadata": metadata(),
        },
    }
