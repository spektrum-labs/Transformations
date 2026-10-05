# isRiskBasedAuthenticationEnabled.py - Okta (Identity Engine and Classic)
#
# Method: workflow getMfaPolicyRules (Integration-Service). These are the same four GETs that
# isconditionalaccessenabled.py reads:
#   GET /api/v1/policies?type=OKTA_SIGN_ON        -> signOnPolicies   (global session policies)
#   GET /api/v1/policies/{policyId}/rules         -> signOnRules      (one list per policy, same order)
#   GET /api/v1/policies?type=ACCESS_POLICY       -> accessPolicies   (authentication policies)
#   GET /api/v1/policies/{policyId}/rules         -> accessRules      (one list per policy, same order)
# Docs: https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Policy/
#   AccessPolicyRule.conditions.riskScore.level (ANY | LOW | MEDIUM | HIGH)
#   OktaSignOnPolicyRule.conditions.riskScore.level, conditions.risk.behaviors[]
#   actions.appSignOn.{access, verificationMethod.factorMode}; actions.signon.{access, requireFactor}


def transform(input):
    """
    isRiskBasedAuthenticationEnabled: True when Okta changes a sign-in decision based on risk.

    True when at least one ACTIVE rule, in an ACTIVE judged policy, has a risk condition AND its outcome
    differs from that policy's catch-all. A risk condition is riskScore.level LOW, MEDIUM or HIGH, or a
    non-empty list of risk behaviors. The outcomes compared are DENY, ALLOW with two factors, and ALLOW
    with one factor.
    A risk rule that ends the same way as the catch-all changes nothing, so it does not count.
    The catch-all is the system rule; when there is none, it is the last rule by priority.
    Judged policies: ACTIVE global session (OKTA_SIGN_ON) policies, plus, on Identity Engine, ACTIVE
    authentication (ACCESS_POLICY) policies whose resourceType is APP or absent.

    False when every judged list was read and no rule qualifies.

    Unevaluated (value None, dataCollection status "error") when: Okta returned an error body; a policy or
    rule list is missing or does not line up; there is no active policy to judge; a list length is a whole
    multiple of 200 (the page size, so the list may be cut off); or the transformation errors.

    Does not prove: which apps or users a risk rule covers, or how Okta scores risk for a given sign-in.
    """
    try:
        state = evaluate(input)
    except Exception as e:
        return unevaluated("Transformation error: " + str(e), [str(e)])
    if state["error"] is not None:
        return unevaluated(state["error"], [])
    ok = len(state["found"]) > 0
    passes = []
    fails = []
    if ok:
        passes.append(state["summary"])
        for item in state["found"][:10]:
            passes.append("Risk-based: " + item)
    else:
        fails.append(state["summary"])
    return respond(ok, passes, fails, state["inputSummary"])


PAGE = 200


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


def truncated(value):
    if isinstance(value, dict):
        if truthy(value.get("paginationTruncated")):
            return True
        return truncated(value.get("response_metadata"))
    return False


def rule_list(item):
    if isinstance(item, dict):
        for wrapper in ["apiResponse", "response", "result", "data"]:
            if wrapper in item:
                return rule_list(item[wrapper])
        return None
    if isinstance(item, list):
        return [r for r in item if isinstance(r, dict)]
    return None


def full_page(items):
    return isinstance(items, list) and len(items) > 0 and len(items) % PAGE == 0


def pair(policies, rules, label):
    if not isinstance(policies, list):
        return None, label + " policy list is missing"
    if full_page(policies):
        return None, label + " policy list has " + str(len(policies)) + " entries, a whole number of pages, so it may be cut off"
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
        if full_page(found):
            return None, label + " rules for policy '" + text(policy.get("name")) + "' fill a whole number of pages, so the list may be cut off"
        out.append((policy, found))
    return out, None


def active(obj):
    return text(obj.get("status")).upper() == "ACTIVE"


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


def risk_signal(rule):
    cond = as_dict(rule.get("conditions"))
    level = text(as_dict(cond.get("riskScore")).get("level")).upper()
    if level in ["LOW", "MEDIUM", "HIGH"]:
        return "risk score " + level
    behaviors = as_dict(cond.get("risk")).get("behaviors")
    if isinstance(behaviors, list) and len(behaviors) > 0:
        return "risk behaviors"
    return None


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
    live = [r for r in rules if active(r)]
    if not live:
        return None
    system = [r for r in live if truthy(r.get("system"))]
    ordered = sorted(live, key=priority)
    catch_all = system[-1] if system else ordered[-1]
    fallback = outcome(catch_all, classic)
    for rule in ordered:
        if rule is catch_all:
            continue
        signal = risk_signal(rule)
        result = outcome(rule, classic)
        if signal is not None and result != fallback:
            return (text(policy.get("name")) + " / " + text(rule.get("name")) + " (" + signal + ": " + result
                    + "; catch-all " + fallback + ")")
    return None


def evaluate(raw):
    state = {"error": None, "found": [], "summary": "", "inputSummary": {}}
    if truncated(raw if isinstance(raw, dict) else None):
        state["error"] = "Okta's policy read was cut off (paginationTruncated)"
        return state
    data = parse(raw)
    if truncated(data):
        state["error"] = "Okta's policy read was cut off (paginationTruncated)"
        return state
    problem = error_in(data)
    if problem is not None:
        state["error"] = problem
        return state
    signon, signon_problem = pair(data.get("signOnPolicies"), data.get("signOnRules"), "Global session (OKTA_SIGN_ON)")
    if signon_problem is not None:
        state["error"] = signon_problem
        return state
    access, access_problem = pair(data.get("accessPolicies"), data.get("accessRules"), "Authentication (ACCESS_POLICY)")
    if access_problem is not None:
        state["error"] = access_problem
        return state
    app_policies = []
    for policy, rules in access:
        kind = text(as_dict(policy.get("_embedded")).get("resourceType")).upper()
        if active(policy) and kind in ["", "APP"]:
            app_policies.append((policy, rules))
    session_policies = [(p, r) for (p, r) in signon if active(p)]
    if not app_policies and not session_policies:
        state["error"] = "No active global session or app authentication policy was returned"
        return state
    for policy, rules in session_policies:
        found = judge(policy, rules, True)
        if found is not None:
            state["found"].append(found)
    for policy, rules in app_policies:
        found = judge(policy, rules, False)
        if found is not None:
            state["found"].append(found)
    judged = len(session_policies) + len(app_policies)
    engine = "Identity Engine" if app_policies else "Classic Engine"
    state["summary"] = (engine + ": " + str(len(state["found"])) + " of " + str(judged)
                        + " active sign-in policies change the outcome on a risk condition")
    state["inputSummary"] = {"engine": engine, "policiesJudged": judged, "policiesRiskBased": len(state["found"])}
    return state


def respond(ok, passes, fails, summary):
    from datetime import datetime
    return {
        "transformedResponse": {"isRiskBasedAuthenticationEnabled": ok},
        "additionalInfo": {
            "dataCollection": {"status": "success", "errors": []},
            "validation": {"status": "success", "errors": [], "warnings": []},
            "transformation": {"status": "success", "errors": [], "inputSummary": summary},
            "evaluation": {"passReasons": passes, "failReasons": fails, "recommendations": [] if ok else
                           ["Add a sign-in policy rule conditioned on risk level that denies or requires more factors "
                            "than the policy's catch-all"],
                           "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0",
                         "transformationId": "isRiskBasedAuthenticationEnabled", "vendor": "Okta", "category": "Identity"},
        },
    }


def unevaluated(reason, errors):
    from datetime import datetime
    return {
        "transformedResponse": {"isRiskBasedAuthenticationEnabled": None},
        "additionalInfo": {
            "dataCollection": {"status": "error", "errors": [reason]},
            "validation": {"status": "error" if errors else "unknown", "errors": [], "warnings": []},
            "transformation": {"status": "error" if errors else "success", "errors": errors, "inputSummary": {}},
            "evaluation": {"passReasons": [], "failReasons": [reason], "recommendations": [], "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0",
                         "transformationId": "isRiskBasedAuthenticationEnabled", "vendor": "Okta", "category": "Identity"},
        },
    }
