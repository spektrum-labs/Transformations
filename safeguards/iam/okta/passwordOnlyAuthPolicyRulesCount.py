# passwordOnlyAuthPolicyRulesCount.py - Okta (Identity Engine and Classic)
#
# Method: workflow getMfaPolicyRules (Integration-Service). These are the same four GETs that
# isconditionalaccessenabled.py reads:
#   GET /api/v1/policies?type=OKTA_SIGN_ON        -> signOnPolicies   (global session policies)
#   GET /api/v1/policies/{policyId}/rules         -> signOnRules      (one list per policy, same order)
#   GET /api/v1/policies?type=ACCESS_POLICY       -> accessPolicies   (authentication policies)
#   GET /api/v1/policies/{policyId}/rules         -> accessRules      (one list per policy, same order)
# Docs: https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Policy/
#   AccessPolicyRule.actions.appSignOn.{access, verificationMethod.{type, factorMode, constraints[]}}
#     constraints[] items: {knowledge: {types: ["password"]}, possession: {...}}
#   OktaSignOnPolicyRule.actions.signon.{access, requireFactor}


def transform(input):
    """
    passwordOnlyAuthPolicyRulesCount: the number of active sign-in rules that let a user in with a
    password alone. Lower is better, and 0 means no rule allows it.

    A rule is counted when it is ACTIVE, in an ACTIVE policy that is judged, and it allows sign-in with
    one factor that may be a password:
      Identity Engine. Judged policies: ACTIVE authentication policies (ACCESS_POLICY) whose resourceType
        is APP or absent. The rule counts when appSignOn.access is ALLOW, verificationMethod is ASSURANCE
        with factorMode 1FA, and either no constraint is set (any one factor, which includes a password)
        or a constraint accepts the password authenticator (knowledge with no types, or with "password").
        A 1FA rule that accepts only possession factors (FastPass, a security key) is passwordless and is
        not counted.
      Classic Engine (no active app authentication policy). Judged policies: ACTIVE global session
        (OKTA_SIGN_ON) policies. The rule counts when signon.access is ALLOW and requireFactor is not
        true. On Classic the primary factor is the password.
    The catch-all rule is counted like any other rule. A catch-all that allows a password alone is the
    case this check most needs to find.

    Unevaluated (value None, dataCollection status "error") when: Okta returned an error body; the policy
    or rule lists are missing; the rule lists do not line up with the policies; there is no active policy
    to judge; an ALLOW rule uses a verification method this file cannot read; a list length is a whole
    multiple of 200 (the page size, so the list may be cut off); or the transformation itself errors.
    None of these is a measurement, so none may read as Passed or Failed.

    Does not prove: which apps or users each rule applies to, or what a network zone contains.
    """
    try:
        state = evaluate(input)
    except Exception as e:
        return unevaluated("Transformation error: " + str(e), [str(e)])
    if state["error"] is not None:
        return unevaluated(state["error"], [])
    count = len(state["counted"])
    passes = []
    fails = []
    if count == 0:
        passes.append(state["summary"])
    else:
        fails.append(state["summary"])
        for item in state["counted"][:10]:
            fails.append("Password alone: " + item)
    return respond(count, passes, fails, state["inputSummary"])


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


def accepts_password(constraints):
    """True when a 1FA rule's constraints accept a password. No constraints means any one factor."""
    if constraints is None:
        return True
    if not isinstance(constraints, list):
        return None
    if len(constraints) == 0:
        return True
    for item in constraints:
        if not isinstance(item, dict):
            return None
        if "knowledge" in item:
            knowledge = item.get("knowledge")
            if not isinstance(knowledge, dict):
                return True
            types = knowledge.get("types")
            if not types:
                return True
            if isinstance(types, list) and "password" in [text(t).lower() for t in types]:
                return True
    return False


def ie_password_only(rule):
    """True, False, or None when the rule's verification method cannot be read."""
    sign_on = as_dict(as_dict(rule.get("actions")).get("appSignOn"))
    if text(sign_on.get("access")).upper() != "ALLOW":
        return False
    method = sign_on.get("verificationMethod")
    if not isinstance(method, dict):
        return None
    if text(method.get("type")).upper() != "ASSURANCE":
        return None
    mode = text(method.get("factorMode")).upper()
    if mode == "2FA":
        return False
    if mode != "1FA":
        return None
    return accepts_password(method.get("constraints"))


def classic_password_only(rule):
    sign_on = as_dict(as_dict(rule.get("actions")).get("signon"))
    if text(sign_on.get("access")).upper() != "ALLOW":
        return False
    return not truthy(sign_on.get("requireFactor"))


def evaluate(raw):
    state = {"error": None, "counted": [], "summary": "", "inputSummary": {}}
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
    access, access_problem = pair(data.get("accessPolicies"), data.get("accessRules"), "Authentication (ACCESS_POLICY)")
    if access_problem is not None:
        state["error"] = access_problem
        return state
    app_policies = []
    for policy, rules in access:
        kind = text(as_dict(policy.get("_embedded")).get("resourceType")).upper()
        if active(policy) and kind in ["", "APP"]:
            app_policies.append((policy, rules))
    classic = not app_policies
    if classic:
        signon, signon_problem = pair(data.get("signOnPolicies"), data.get("signOnRules"), "Global session (OKTA_SIGN_ON)")
        if signon_problem is not None:
            state["error"] = "No active app authentication policy, and " + signon_problem
            return state
        judged = [(p, r) for (p, r) in signon if active(p)]
        engine = "Classic Engine"
    else:
        judged = app_policies
        engine = "Identity Engine"
    if not judged:
        state["error"] = "No active " + ("global session" if classic else "app authentication") + " policy was returned"
        return state
    rules_judged = 0
    for policy, rules in judged:
        for rule in rules:
            if not active(rule):
                continue
            rules_judged = rules_judged + 1
            verdict = classic_password_only(rule) if classic else ie_password_only(rule)
            if verdict is None:
                state["error"] = ("Rule '" + text(rule.get("name")) + "' in policy '" + text(policy.get("name"))
                                  + "' uses a verification method this check cannot read")
                return state
            if verdict:
                state["counted"].append(text(policy.get("name")) + " / " + text(rule.get("name")))
    if rules_judged == 0:
        state["error"] = "The judged policies returned no active rules"
        return state
    state["summary"] = (engine + ": " + str(len(state["counted"])) + " of " + str(rules_judged)
                        + " active sign-in rules in " + str(len(judged)) + " active policies allow a password alone")
    state["inputSummary"] = {"engine": engine, "policiesJudged": len(judged), "rulesJudged": rules_judged,
                             "passwordOnlyRules": len(state["counted"])}
    return state


def respond(count, passes, fails, summary):
    from datetime import datetime
    return {
        "transformedResponse": {"passwordOnlyAuthPolicyRulesCount": count},
        "additionalInfo": {
            "dataCollection": {"status": "success", "errors": []},
            "validation": {"status": "success", "errors": [], "warnings": []},
            "transformation": {"status": "success", "errors": [], "inputSummary": summary},
            "evaluation": {"passReasons": passes, "failReasons": fails, "recommendations": [] if count == 0 else
                           ["Require two factors, or a passwordless factor, on every rule that allows sign-in"],
                           "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0",
                         "transformationId": "passwordOnlyAuthPolicyRulesCount", "vendor": "Okta", "category": "Identity"},
        },
    }


def unevaluated(reason, errors):
    from datetime import datetime
    return {
        "transformedResponse": {"passwordOnlyAuthPolicyRulesCount": None},
        "additionalInfo": {
            "dataCollection": {"status": "error", "errors": [reason]},
            "validation": {"status": "error" if errors else "unknown", "errors": [], "warnings": []},
            "transformation": {"status": "error" if errors else "success", "errors": errors, "inputSummary": {}},
            "evaluation": {"passReasons": [], "failReasons": [reason], "recommendations": [], "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0",
                         "transformationId": "passwordOnlyAuthPolicyRulesCount", "vendor": "Okta", "category": "Identity"},
        },
    }
