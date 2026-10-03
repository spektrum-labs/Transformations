# isconditionalaccessenabled.py - Okta (Identity Engine and Classic)
#
# Method: workflow getMfaPolicyRules (Integration-Service), the same four GETs ismfaenforcedforusers.py reads:
#   GET /api/v1/policies?type=OKTA_SIGN_ON        -> signOnPolicies   (global session policies)
#   GET /api/v1/policies/{policyId}/rules         -> signOnRules      (one list per policy, same order)
#   GET /api/v1/policies?type=ACCESS_POLICY       -> accessPolicies   (authentication policies)
#   GET /api/v1/policies/{policyId}/rules         -> accessRules      (one list per policy, same order)
# Docs: https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Policy/
#   listPolicies, listPolicyRules (scope okta.policies.read). Rule schemas:
#   AccessPolicyRule.conditions.{network.connection/include/exclude, device.{registered, managed, assurance.include},
#     riskScore.level, platform.include}; actions.appSignOn.{access, verificationMethod.{type, factorMode}}
#   OktaSignOnPolicyRule.conditions.{network, riskScore}; actions.signon.{access, requireFactor}


def transform(input):
    """
    isConditionalAccessEnabled - True when at least one active sign-in policy makes its access decision
    depend on context, and that policy's catch-all does not let everyone in on one factor.

    A policy counts as ENFORCING conditional access when both hold:
      1. an active, non-catch-all rule carries a context condition - a network zone (connection ZONE with
         zones included or excluded), a device condition (registered, managed, or a device assurance
         policy), a risk level (LOW, MEDIUM or HIGH), or a platform - and its outcome differs from the
         catch-all's. Outcomes are DENY, ALLOW with two factors, ALLOW with one factor.
      2. the catch-all (the system rule, else the last rule by priority) is not ALLOW with one factor.
    Identity Engine: judged over ACTIVE authentication policies whose resourceType is APP or absent
    (enrolment, recovery and unlock policies are not app sign-in). Classic Engine (no active app
    authentication policy): judged over ACTIVE global session (OKTA_SIGN_ON) policies.

    Also returns conditionalAccessPolicyPercentage: enforcing policies / judged policies * 100.

    Unevaluated (value None, dataCollection status "error") on: an error body, missing policy or rule lists, rule
    lists that do not line up with the policies, no active policy to judge, and a transformation error. None of
    those is a measurement, so none may read as Failed (or Passed).

    Does not prove: which apps each policy is assigned to, or what the named network zones contain.
    """
    try:
        state = evaluate(input)
    except Exception as e:
        return unevaluated("Transformation error: " + str(e), [str(e)])
    if state["error"] is not None:
        return unevaluated(state["error"], [])
    ok = len(state["enforcing"]) > 0
    passes = []
    fails = []
    if ok:
        passes.append(state["summary"])
        for item in state["enforcing"][:10]:
            passes.append("Conditional: " + item)
    else:
        fails.append(state["summary"])
        for item in state["notes"][:10]:
            fails.append(item)
    return respond(ok, state["percentage"], passes, fails, state["inputSummary"], [])


def text(value):
    if value is None:
        return ""
    return str(value).strip()


def truthy(value):
    if isinstance(value, bool):
        return value
    return text(value).lower() == "true"


def parse(value):
    import json
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    if isinstance(value, str):
        value = json.loads(value)
    for wrapper in ["data", "response", "result", "apiResponse", "_response_data"]:
        if isinstance(value, dict) and wrapper in value and "accessPolicies" not in value and "signOnPolicies" not in value:
            value = value[wrapper]
    return value


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


def as_dict(value):
    return value if isinstance(value, dict) else {}


def error_in(data):
    if not isinstance(data, dict):
        return "Response is not an object with policy and rule lists"
    for k in ["errorCode", "errorSummary", "error", "errors", "errorMessage"]:
        if data.get(k):
            return "Okta returned an error: " + text(data.get(k))[:200]
    for k in ["statusCode", "status_code"]:
        if data.get(k) not in (None, 200):
            return "Okta returned HTTP " + text(data.get(k))
    return None


def context_signals(rule):
    cond = as_dict(rule.get("conditions"))
    found = []
    net = as_dict(cond.get("network"))
    if text(net.get("connection")).upper() == "ZONE" and (net.get("include") or net.get("exclude")):
        found.append("network zone")
    dev = as_dict(cond.get("device"))
    if truthy(dev.get("registered")) or truthy(dev.get("managed")) or as_dict(dev.get("assurance")).get("include"):
        found.append("device")
    risk = as_dict(cond.get("riskScore"))
    if text(risk.get("level")).upper() in ["LOW", "MEDIUM", "HIGH"]:
        found.append("risk " + text(risk.get("level")).upper())
    plat = as_dict(cond.get("platform"))
    if plat.get("include") or plat.get("exclude"):
        found.append("platform")
    return found


def outcome(rule, classic):
    actions = as_dict(rule.get("actions"))
    if classic:
        sign_on = as_dict(actions.get("signon"))
        if text(sign_on.get("access")).upper() != "ALLOW":
            return "DENY"
        return "ALLOW_2FA" if truthy(sign_on.get("requireFactor")) else "ALLOW_1FA"
    sign_on = as_dict(actions.get("appSignOn"))
    if text(sign_on.get("access")).upper() != "ALLOW":
        return "DENY"
    method = as_dict(sign_on.get("verificationMethod"))
    if text(method.get("type")).upper() == "ASSURANCE" and text(method.get("factorMode")).upper() == "2FA":
        return "ALLOW_2FA"
    return "ALLOW_1FA"


def priority(rule):
    try:
        return float(rule.get("priority"))
    except Exception:
        return 0.0


def judge(policy, rules, classic):
    """Returns (enforcing description or None, note)."""
    name = text(policy.get("name"))
    live = [r for r in rules if active(r)]
    if not live:
        return None, name + ": no active rules"
    system = [r for r in live if truthy(r.get("system"))]
    ordered = sorted(live, key=priority)
    catch_all = system[-1] if system else ordered[-1]
    fallback = outcome(catch_all, classic)
    if fallback == "ALLOW_1FA":
        return None, name + ": catch-all '" + text(catch_all.get("name")) + "' allows everyone on one factor"
    for rule in ordered:
        if rule is catch_all:
            continue
        signals = context_signals(rule)
        result = outcome(rule, classic)
        if signals and result != fallback:
            return (name + " / " + text(rule.get("name")) + " (" + ", ".join(signals) + ": " + result
                    + "; catch-all " + fallback + ")"), None
    return None, name + ": no active rule changes the outcome on network zone, device, risk or platform"


def evaluate(raw):
    data = parse(raw)
    state = {"error": None, "enforcing": [], "notes": [], "percentage": 0, "summary": "", "inputSummary": {}}
    problem = error_in(data)
    if problem is not None:
        state["error"] = problem
        return state
    access, access_problem = pair(data.get("accessPolicies"), data.get("accessRules"), "Authentication (ACCESS_POLICY)")
    signon, signon_problem = pair(data.get("signOnPolicies"), data.get("signOnRules"), "Global session (OKTA_SIGN_ON)")
    if access_problem is not None:
        state["error"] = access_problem
        return state
    app_policies = []
    for policy, rules in access or []:
        kind = text(as_dict(policy.get("_embedded")).get("resourceType")).upper()
        if active(policy) and kind in ["", "APP"]:
            app_policies.append((policy, rules))
    classic = not app_policies
    if classic:
        if signon is None:
            state["error"] = "No active app authentication policy, and " + (signon_problem or "no global session policy")
            return state
        judged = [(p, r) for (p, r) in signon if active(p)]
        engine = "Classic Engine"
    else:
        judged = app_policies
        engine = "Identity Engine"
    if not judged:
        state["error"] = "No active " + ("global session" if classic else "app authentication") + " policy was returned"
        return state
    for policy, rules in judged:
        found, note = judge(policy, rules, classic)
        if found is not None:
            state["enforcing"].append(found)
        else:
            state["notes"].append(note)
    count = len(state["enforcing"])
    state["percentage"] = round(count * 100.0 / len(judged), 1)
    state["summary"] = (engine + ": " + str(count) + " of " + str(len(judged))
                        + " active sign-in policies enforce conditional access (context-dependent rule, catch-all not one-factor allow)")
    state["inputSummary"] = {"engine": engine, "policiesJudged": len(judged), "policiesEnforcing": count,
                             "conditionalAccessPolicyPercentage": state["percentage"]}
    return state


def respond(ok, percentage, passes, fails, summary, errors):
    from datetime import datetime
    return {
        "transformedResponse": {"isConditionalAccessEnabled": ok, "conditionalAccessPolicyPercentage": percentage},
        "additionalInfo": {
            "dataCollection": {"status": "success", "errors": []},
            "validation": {"status": "success" if not errors else "error", "errors": [], "warnings": []},
            "transformation": {"status": "error" if errors else "success", "errors": errors, "inputSummary": summary},
            "evaluation": {"passReasons": passes, "failReasons": fails, "recommendations": [] if ok else
                           ["Add an authentication policy rule conditioned on network zone, device assurance or risk, "
                            "and set that policy's catch-all rule to deny or require two factors"],
                           "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0",
                         "transformationId": "isConditionalAccessEnabled", "vendor": "Okta", "category": "Identity"},
        },
    }


def unevaluated(reason, errors):
    from datetime import datetime
    return {
        "transformedResponse": {"isConditionalAccessEnabled": None, "conditionalAccessPolicyPercentage": None},
        "additionalInfo": {
            "dataCollection": {"status": "error", "errors": [reason]},
            "validation": {"status": "error" if errors else "unknown", "errors": [], "warnings": []},
            "transformation": {"status": "error" if errors else "success", "errors": errors, "inputSummary": {}},
            "evaluation": {"passReasons": [], "failReasons": [reason], "recommendations": [], "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0",
                         "transformationId": "isConditionalAccessEnabled", "vendor": "Okta", "category": "Identity"},
        },
    }
