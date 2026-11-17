# issessiontimeoutconfigured.py - Okta (Identity Engine and Classic)
#
# Method: workflow getMfaPolicyRules (Integration-Service), the same four GETs isconditionalaccessenabled.py reads:
#   GET /api/v1/policies?type=OKTA_SIGN_ON        -> signOnPolicies   (global session policies)
#   GET /api/v1/policies/{policyId}/rules         -> signOnRules      (one list per policy, same order)
#   GET /api/v1/policies?type=ACCESS_POLICY       -> accessPolicies   (app sign-on / authentication policies)
#   GET /api/v1/policies/{policyId}/rules         -> accessRules      (one list per policy, same order)
# Docs: https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Policy/
#   listPolicies, listPolicyRules (apiToken, or OAuth scope okta.policies.read; GA). Rule schemas:
#   OktaSignOnPolicyRule.actions.signon.{access, session.{maxSessionIdleMinutes, maxSessionLifetimeMinutes}}.
#     maxSessionIdleMinutes: the minutes of inactivity after which the session ends (0 or absent: no idle limit).
#     maxSessionLifetimeMinutes: "Maximum number of minutes (from when the user signs in) that a user's session is
#     active ... Disable by setting to 0" (default 0, i.e. no maximum lifetime). Reported as evidence only.
#   AccessPolicyRule.actions.appSignOn.verificationMethod.reauthenticateIn (ASSURANCE and AUTH_METHOD_CHAIN): an
#     ISO 8601 duration after which the user must authenticate again to reach the app, "regardless of user
#     activity". "PT0S" is every sign-in; "PT43800H" is Okta's value for "once per session" (no app-level limit).
#   Integration-Service returns these values as strings ("240", "0", "False"); both forms are read.
# Default Policy and Default Rule (same spec, Policy tag): "Only the default policy contains a default rule", and
#   "The default rule is required and is always the last rule in the priority order". Custom global session
#   policies carry no Default Rule. Every authentication policy ends in its system Catch-all Rule.
# Paging: listPolicyRules takes `limit` ("Defines the number of policy rules returned") with no documented default
#   or maximum and no `after` cursor, and the read follows no Link header. A rule list exactly one page long cannot
#   be told from a list cut at that page, so it is not judged. Page sizes: DEFAULT_PAGE_SIZE (Okta documents
#   `default: 20` for `limit` on its other list endpoints that state one) and LIMIT_PAGE_SIZE (the `limit=200` the
#   definition may send).

KEY = "isSessionTimeoutConfigured"
DEFAULT_PAGE_SIZE = 20
LIMIT_PAGE_SIZE = 200
PAGE_SIZES = (DEFAULT_PAGE_SIZE, LIMIT_PAGE_SIZE)
# Reported when a session has no idle limit: 43,800 hours, the value Okta itself writes for "once per session"
# (reauthenticateIn PT43800H). No Okta session setting is longer, so every numeric threshold reads it as Failed,
# where a string such as "unlimited" made Token-Service answer "could not be evaluated".
NO_LIMIT_MINUTES = 43800 * 60


def transform(input):
    """
    isSessionTimeoutConfigured - the longest time, in minutes, an Okta session may sit idle before Okta ends it
    (Josh's decision 2026-11-16: the IDLE timeout is graded). The requirement's threshold decides (for example
    lessThan 480).

    Value: the largest maxSessionIdleMinutes over the ACTIVE global session (OKTA_SIGN_ON) policies' ACTIVE rules
    whose action is ALLOW (a DENY rule starts no session; inactive rules and policies are ignored). A rule whose
    idle timeout is 0 or missing has no idle limit and counts as NO_LIMIT_MINUTES (43,800 hours), so it fails every
    numeric threshold. Never 0, false or a string, which Token-Service reads as a pass or cannot compare.
    Rule and policy reachability (group assignment, priority shadowing) is not read, so a shadowed rule still counts.

    Evidence, reported in additionalInfo and never graded:
      * maxSessionLifetimeMinutes / sessionLifetimeUnlimited: the longest global session lifetime (0 = no maximum);
      * appReauthenticateMinutes: the longest app re-authentication interval (Identity Engine ACTIVE app
        authentication policies, their ACTIVE ALLOW rules, verificationMethod.reauthenticateIn; see
        reauthenticate_in). None when no app policy is readable or none bounds it. An unreadable authentication
        policy list does not stop the idle grade; it only leaves this evidence empty.

    Output: isSessionTimeoutConfigured (minutes), maxSessionIdleMinutes (None when any rule has no idle limit),
    sessionIdleUnlimited, plus the evidence above, allowRuleCount, appAllowRuleCount, policiesJudged,
    appPoliciesJudged.

    Unevaluated (value None, dataCollection status "error") on: an error body, missing policy or rule lists, rule
    lists that do not line up with the policies, no active global session policy, no active ALLOW rule, an ALLOW
    rule without session settings, or an idle timeout that is not a whole number of minutes. Also on a global
    session list that may be incomplete:
      * the policy list has no Default Policy (system: true), or exactly a page of policies (a length in
        PAGE_SIZES). Okta always returns the Default Policy, so the list was cut short;
      * the Default Policy's rule list has no Default Rule (always last), so the rule list was cut short;
      * an active policy returned no rules, or exactly a page of rules, which cannot be told apart from a first
        page cut short.
    Custom global session policies are judged on the rules they return: Okta gives them no Default Rule, and a user
    who matches none of them falls through to a later policy, ending at the Default Policy, whose rules are always
    judged.

    Does not prove: which groups or apps each policy applies to, or the separate 24-hour administrator limit some
    requirements describe.
    """
    try:
        state = evaluate(input)
    except Exception as e:
        return unevaluated("Transformation error: " + str(e), [str(e)])
    if state["error"] is not None:
        return unevaluated(state["error"], [])
    value = state["value"]
    summary = state["inputSummary"]
    if value == NO_LIMIT_MINUTES:
        fails = ["Okta sessions have no idle limit: " + state["why"] + "; reported as " + str(NO_LIMIT_MINUTES)
                 + " minutes (43,800 hours, Okta's 'once per session'), which no session threshold accepts"]
        for policy_name, rule_name in state["where"][:10]:
            fails.append("Okta policy: '" + policy_name + "' rule '" + rule_name + "' sets no idle timeout")
        return respond(value, summary, [], fails,
                       ["Set a maximum session idle time (maxSessionIdleMinutes above 0) on every active ALLOW rule "
                        "of every active global session policy"])
    passes = ["Okta sessions: an idle session ends within " + str(value) + " minutes (" + state["why"] + ")"]
    return respond(value, summary, passes, [], [])


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


def pair(policies, rules, label):
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


def system(obj):
    return truthy(obj.get("system"))


def resource_type(policy):
    return text(as_dict(policy.get("_embedded")).get("resourceType")).upper()


def incomplete(pairs, kind, last_rule):
    """Why a policy or rule list may be cut short, or None when it reads as complete. kind names the policy type;
    last_rule names the system rule Okta always lists last ("Default Rule" for the global session Default Policy,
    "Catch-all Rule" for every authentication policy)."""
    if len(pairs) in PAGE_SIZES:
        return (kind + ": the policy list holds exactly " + str(len(pairs)) + " policies, one full page; it may be "
                "cut short, so the longest session cannot be read")
    defaults = [(p, r) for (p, r) in pairs if system(p)]
    if not defaults:
        return (kind + ": the policy list does not include its system default policy (system: true); Okta always "
                "returns it, so the list is incomplete and the longest session cannot be read")
    checked = defaults if last_rule == "Default Rule" else [(p, r) for (p, r) in pairs if active(p)]
    for policy, rules in checked:
        if rules and not any(system(rule) for rule in rules):
            return ("Okta policy: '" + text(policy.get("name")) + "' returned no " + last_rule + " (system: true); "
                    "Okta always lists it last, so the rule list is incomplete and the longest session cannot be read")
    for policy, rules in pairs:
        if not active(policy):
            continue
        if not rules:
            return ("Okta policy: '" + text(policy.get("name")) + "' is active but returned no rules, so the "
                    "sessions it starts cannot be read")
        if len(rules) in PAGE_SIZES:
            return ("Okta policy: '" + text(policy.get("name")) + "' returned exactly " + str(len(rules))
                    + " rules, one full page; the rule list may be cut short, so the longest session cannot be read")
    return None


def duration_minutes(value):
    """Whole minutes (rounded up) in an ISO 8601 duration such as PT2H, PT0S, P1D or P1W, or None."""
    import re
    raw = text(value).upper()
    found = re.match(r"^P(?:(\d+)W)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$", raw)
    if not found or raw in ("P", "PT") or raw.endswith("T"):
        return None
    parts = [int(x) if x else 0 for x in found.groups()]
    seconds = (((parts[0] * 7 + parts[1]) * 24 + parts[2]) * 60 + parts[3]) * 60 + parts[4]
    return (seconds + 59) // 60


def reauthenticate_in(method):
    """A rule's re-authentication interval in minutes, or None when it is missing or unreadable. AUTH_METHOD_CHAIN
    carries it at the top and per chain; without the top-level value the longest chain value is the worst case.
    ASSURANCE constraints override the rule-level value per factor kind (Okta: "the re-authentication intervals for
    constraints take precedent"). A kind's interval is only a bound on a path that must pass through it: `required`
    is false whenever a kind has excludedAuthenticationMethods, so a listed kind is not necessarily on every path.
      * 1FA: a user may satisfy the rule with a single kind, so the worst case is the longest over every kind
        (listed with its own interval, or absent and inheriting the rule-level value).
      * 2FA: every path uses a possession factor, so possession is always bound; knowledge is bound only when it is
        required (possession plus user verification is a valid pair that never asks for the password). A kind
        without its own interval inherits the rule-level value. The shortest over the bound kinds applies.
    A constraint is the worst alternative: the longest over the rule's constraints. A constraint that is not an
    object is unreadable (None)."""
    rule_level = duration_minutes(method.get("reauthenticateIn")) if "reauthenticateIn" in method else None
    constraints = method.get("constraints")
    if text(method.get("type")).upper() == "ASSURANCE" and isinstance(constraints, list) and constraints:
        two_factor = text(method.get("factorMode")).upper() == "2FA"
        worst = None
        for constraint in constraints:
            if not isinstance(constraint, dict):
                return None
            mins = {}
            required = {}
            for kind in ("knowledge", "possession"):
                factor = constraint.get(kind)
                if factor is not None and not isinstance(factor, dict):
                    return None
                own = as_dict(factor).get("reauthenticateIn")
                mins[kind] = rule_level if own is None else duration_minutes(own)
                required[kind] = isinstance(factor, dict) and text(factor.get("required")).lower() != "false"
            if two_factor:
                used = ["possession", "knowledge"] if required["knowledge"] else ["possession"]
            else:
                used = list(mins)
            pool = [mins[k] for k in used]
            if None in pool:
                return None
            value = min(pool) if two_factor else max(pool)
            worst = value if worst is None else max(worst, value)
        return worst
    if "reauthenticateIn" in method:
        return rule_level
    chains = method.get("chains")
    if text(method.get("type")).upper() != "AUTH_METHOD_CHAIN" or not isinstance(chains, list) or not chains:
        return None
    values = [duration_minutes(as_dict(c).get("reauthenticateIn")) for c in chains]
    if None in values:
        return None
    return max(values)


def identity_engine(signon_pairs):
    """Identity Engine global session rules carry actions.signon.primaryFactor; Classic rules do not."""
    for policy, rules in signon_pairs:
        for rule in rules:
            if "primaryFactor" in as_dict(as_dict(rule.get("actions")).get("signon")):
                return True
    return False


def global_bound(state, signon_pairs):
    """Over active ALLOW rules of active global session policies: (idle minutes, rules with no idle limit, lifetime
    evidence (minutes or None when a rule has none, readable lifetimes), rule count, policies judged); sets
    state["error"] and returns None when it cannot be read."""
    problem = incomplete(signon_pairs, "Okta global session (OKTA_SIGN_ON) policies", "Default Rule")
    if problem is not None:
        state["error"] = problem
        return None
    judged = [(p, r) for (p, r) in signon_pairs if active(p)]
    if not judged:
        state["error"] = "Okta global session policies: no active global session (OKTA_SIGN_ON) policy was returned"
        return None
    idles = []
    lifetimes = []
    for policy, rules in judged:
        for rule in rules:
            if not active(rule):
                continue
            sign_on = as_dict(as_dict(rule.get("actions")).get("signon"))
            if text(sign_on.get("access")).upper() != "ALLOW":
                continue
            label = (text(policy.get("name")), text(rule.get("name")))
            session = sign_on.get("session")
            if not isinstance(session, dict):
                state["error"] = ("Okta session policy: '" + label[0] + "' ALLOW rule '" + label[1] + "' carries no "
                                  "session settings")
                return None
            raw = session.get("maxSessionIdleMinutes")
            idle = 0 if text(raw) == "" else minutes(raw)
            if idle is None:
                state["error"] = ("Okta session policy: '" + label[0] + "' ALLOW rule '" + label[1] + "' has an "
                                  "idle timeout that is not a whole number of minutes: " + text(raw)[:40])
                return None
            idles.append((idle, label))
            lifetime = minutes(session.get("maxSessionLifetimeMinutes"))
            if lifetime is not None:
                lifetimes.append(lifetime)
    if not idles:
        state["error"] = ("Okta global session policies: no active ALLOW rule in the active policies; no session is "
                          "started to measure")
        return None
    unlimited = [label for (value, label) in idles if value == 0]
    lifetime = None if 0 in lifetimes else (max(lifetimes) if lifetimes else None)
    if unlimited:
        return None, unlimited, lifetime, len(idles), len(judged)
    worst = max([value for (value, label) in idles])
    return worst, [label for (value, label) in idles if value == worst], lifetime, len(idles), len(judged)


def app_bound(state, access_pairs):
    """Worst app re-authentication interval over active ALLOW rules of active app authentication policies:
    (minutes or None when no app policy bounds it, where, rule count, policies judged); sets state["error"] and
    returns None when it cannot be read."""
    apps = [(p, r) for (p, r) in access_pairs if active(p) and resource_type(p) in ("", "APP")]
    if not apps:
        return None, [], 0, 0
    problem = incomplete(access_pairs, "Okta authentication (ACCESS_POLICY) policies", "Catch-all Rule")
    if problem is not None:
        state["error"] = problem
        return None
    values = []
    for policy, rules in apps:
        for rule in rules:
            if not active(rule):
                continue
            app_sign_on = as_dict(as_dict(rule.get("actions")).get("appSignOn"))
            if text(app_sign_on.get("access")).upper() != "ALLOW":
                continue
            label = (text(policy.get("name")), text(rule.get("name")))
            method = as_dict(app_sign_on.get("verificationMethod"))
            interval = reauthenticate_in(method)
            if interval is None:
                state["error"] = ("Okta authentication policy: '" + label[0] + "' ALLOW rule '" + label[1] + "' has "
                                  "no readable re-authentication interval (reauthenticateIn: "
                                  + text(method.get("reauthenticateIn"))[:40] + ")")
                return None
            values.append((min(interval, NO_LIMIT_MINUTES), label))
    if not values:
        return None, [], 0, len(apps)
    worst = max([value for (value, label) in values])
    return worst, [label for (value, label) in values if value == worst], len(values), len(apps)


def evaluate(raw):
    data = parse(raw)
    state = {"error": None, "value": None, "why": "", "where": [], "inputSummary": {}}
    problem = error_in(data)
    if problem is not None:
        state["error"] = problem
        return state
    signon_pairs, problem = pair(data.get("signOnPolicies"), data.get("signOnRules"),
                                 "Okta global session (OKTA_SIGN_ON)")
    if problem is not None:
        state["error"] = problem
        return state
    access_pairs, access_problem = pair(data.get("accessPolicies"), data.get("accessRules"),
                                        "Okta authentication (ACCESS_POLICY)")
    engine = "Identity Engine" if identity_engine(signon_pairs) else "Classic Engine"
    found = global_bound(state, signon_pairs)
    if found is None:
        return state
    idle, idle_where, lifetime, allow_rules, policies = found
    # evidence only: an unreadable authentication policy list leaves it empty and never blocks the idle grade
    reauth, app_rules, app_policies = None, 0, 0
    if access_problem is None:
        found = app_bound(state, access_pairs)
        if found is None:
            state["error"] = None
        else:
            reauth, app_rules, app_policies = found[0], found[2], found[3]
    if idle is not None:
        value, where = idle, idle_where
        why = "the longest global session idle timeout is " + str(idle) + " minutes"
    else:
        value, where = NO_LIMIT_MINUTES, idle_where
        why = "a global session ALLOW rule has no idle timeout (maxSessionIdleMinutes 0 or missing)"
    state["value"] = value
    state["why"] = why
    state["where"] = where
    state["inputSummary"] = {
        "engine": engine,
        "policiesJudged": policies,
        "allowRuleCount": allow_rules,
        "appPoliciesJudged": app_policies,
        "appAllowRuleCount": app_rules,
        "maxSessionLifetimeMinutes": lifetime,
        "sessionLifetimeUnlimited": lifetime is None,
        "appReauthenticateMinutes": reauth,
        "maxSessionIdleMinutes": idle,
        "sessionIdleUnlimited": idle is None,
    }
    return state


def metadata():
    from datetime import datetime
    return {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0",
            "transformationId": KEY, "vendor": "Okta", "category": "Identity"}


def respond(value, summary, passes, fails, recommendations):
    result = {KEY: value}
    for field in ["maxSessionLifetimeMinutes", "sessionLifetimeUnlimited", "appReauthenticateMinutes",
                  "maxSessionIdleMinutes", "sessionIdleUnlimited", "allowRuleCount", "appAllowRuleCount", "policiesJudged",
                  "appPoliciesJudged"]:
        result[field] = summary.get(field)
    return {
        "transformedResponse": result,
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
        "transformedResponse": {KEY: None, "maxSessionIdleMinutes": None},
        "additionalInfo": {
            "dataCollection": {"status": "error", "errors": [reason]},
            "validation": {"status": "error" if errors else "unknown", "errors": [], "warnings": []},
            "transformation": {"status": "error" if errors else "success", "errors": errors, "inputSummary": {}},
            "evaluation": {"passReasons": [], "failReasons": [reason], "recommendations": [], "additionalFindings": []},
            "metadata": metadata(),
        },
    }
