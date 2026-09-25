# ismfaenforcedforusers.py - Okta (Identity Engine and Classic)
#
# Method: workflow getMfaPolicyRules (Integration-Service), four GETs:
#   GET /api/v1/policies?type=OKTA_SIGN_ON        -> signOnPolicies   (global session policies)
#   GET /api/v1/policies/{policyId}/rules         -> signOnRules      (one list per policy, same order)
#   GET /api/v1/policies?type=ACCESS_POLICY       -> accessPolicies   (authentication policies)
#   GET /api/v1/policies/{policyId}/rules         -> accessRules      (one list per policy, same order)
# Docs: https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Policy/
#   listPolicies, listPolicyRules (scope okta.policies.read). Rule schemas:
#   AccessPolicyRule.actions.appSignOn.{access, verificationMethod.{type, factorMode}}
#   OktaSignOnPolicyRule.actions.signon.{access, requireFactor}
#
# Replaces the MFA_ENROLL read (safeguards/86ded564.../ismfaenforcedforusers.py). That read passed
# on Okta's undeletable system Default enrollment policy, which exists in every org and says
# nothing about whether a second factor is ever demanded at sign-in.


def transform(input):
    """
    Returns two keys from one read (the RTA points both criteria at this file):
      isMFAEnforcedForUsers - True only when no path into any app accepts a single factor.
      isMFAEnabled          - True when at least one allowing sign-on rule requires two factors.

    Identity Engine (at least one ACTIVE authentication policy whose _embedded.resourceType is APP
    or absent): every ACTIVE rule that ALLOWs access, in every ACTIVE app authentication policy,
    has verificationMethod type ASSURANCE with factorMode 2FA. A rule's conditions (network zone,
    group, device) are ignored on purpose: a 1FA rule scoped to one zone is still a 1FA path.
    Policies with resourceType END_USER_ACCOUNT_MANAGEMENT (enrolment, recovery, unlock) are not
    app sign-in and are reported, not judged.

    Classic Engine (the authentication policy list is readable but holds no active app policy):
    every ACTIVE rule that ALLOWs access
    in every ACTIVE global session (OKTA_SIGN_ON) policy has requireFactor true.

    Fails closed on: an error body, missing policy or rule lists, a rule list whose length does not
    match its policy list, an active policy with no active rules, and any verification method this
    code does not recognise (AUTH_METHOD_CHAIN, ID_PROOFING).

    Does not prove: which authenticators can satisfy the second factor (see authTypesAllowed), or
    that every user has enrolled one.
    """
    key = "isMFAEnforcedForUsers"
    checks = MFA_CHECKS()
    try:
        state = checks["evaluate"](input)
    except Exception as e:
        return checks["respond"]({key: False, "isMFAEnabled": False}, [], ["Transformation error: " + str(e)], {}, [str(e)])
    ok = state["error"] is None and state["enforced"]
    enabled = state["error"] is None and state["enabled"]
    passes = []
    fails = []
    if state["error"] is not None:
        fails.append(state["error"])
    elif ok:
        passes.append(state["summary"])
    else:
        fails.append(state["summary"])
        for weak in state["weak"][:10]:
            fails.append("Single-factor path: " + weak)
    return checks["respond"]({key: ok, "isMFAEnabled": enabled}, passes, fails, state["inputSummary"], [])


def MFA_CHECKS():
    import json
    from datetime import datetime

    def as_text(value):
        if value is None:
            return ""
        return str(value).strip()

    def is_true(value):
        if isinstance(value, bool):
            return value
        return as_text(value).lower() == "true"

    def parse(value):
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
                return None, label + " rules for policy '" + as_text(policy.get("name")) + "' are unreadable"
            out.append((policy, found))
        return out, None

    def is_active(obj):
        return as_text(obj.get("status")).upper() == "ACTIVE"

    def resource_type(policy):
        embedded = policy.get("_embedded")
        if isinstance(embedded, dict):
            return as_text(embedded.get("resourceType")).upper()
        return ""

    def error_in(data):
        if not isinstance(data, dict):
            return "Response is not an object with policy and rule lists"
        for k in ["errorCode", "errorSummary", "error", "errors", "errorMessage"]:
            if data.get(k):
                return "Okta returned an error: " + as_text(data.get(k))[:200]
        return None

    def evaluate(raw):
        data = parse(raw)
        state = {"error": None, "enforced": False, "enabled": False, "weak": [], "summary": "", "inputSummary": {}}
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
        other_policies = []
        for policy, rules in access or []:
            if not is_active(policy):
                continue
            kind = resource_type(policy)
            if kind in ["", "APP"]:
                app_policies.append((policy, rules))
            else:
                other_policies.append(as_text(policy.get("name")) + " (" + kind + ")")

        weak = []
        strong = 0
        judged_rules = 0
        if app_policies:
            engine = "Identity Engine"
            for policy, rules in app_policies:
                active_rules = [r for r in rules if is_active(r)]
                if not active_rules:
                    state["error"] = "Authentication policy '" + as_text(policy.get("name")) + "' has no active rules"
                    return state
                for rule in active_rules:
                    actions = rule.get("actions") if isinstance(rule.get("actions"), dict) else {}
                    sign_on = actions.get("appSignOn") if isinstance(actions.get("appSignOn"), dict) else {}
                    if as_text(sign_on.get("access")).upper() != "ALLOW":
                        continue
                    judged_rules = judged_rules + 1
                    method = sign_on.get("verificationMethod") if isinstance(sign_on.get("verificationMethod"), dict) else {}
                    method_type = as_text(method.get("type")).upper()
                    mode = as_text(method.get("factorMode")).upper()
                    where = as_text(policy.get("name")) + " / " + as_text(rule.get("name"))
                    if method_type == "ASSURANCE" and mode == "2FA":
                        strong = strong + 1
                    elif method_type == "ASSURANCE":
                        weak.append(where + " (factorMode " + (mode or "missing") + ")")
                    else:
                        weak.append(where + " (verification method " + (method_type or "missing") + " not evaluated)")
        elif signon is not None:
            engine = "Classic Engine"
            active_policies = [(p, r) for (p, r) in signon if is_active(p)]
            if not active_policies:
                state["error"] = "No active global session policy was returned"
                return state
            for policy, rules in active_policies:
                active_rules = [r for r in rules if is_active(r)]
                if not active_rules:
                    state["error"] = "Global session policy '" + as_text(policy.get("name")) + "' has no active rules"
                    return state
                for rule in active_rules:
                    actions = rule.get("actions") if isinstance(rule.get("actions"), dict) else {}
                    sign_on = actions.get("signon") if isinstance(actions.get("signon"), dict) else {}
                    if as_text(sign_on.get("access")).upper() != "ALLOW":
                        continue
                    judged_rules = judged_rules + 1
                    where = as_text(policy.get("name")) + " / " + as_text(rule.get("name"))
                    if is_true(sign_on.get("requireFactor")):
                        strong = strong + 1
                    else:
                        weak.append(where + " (requireFactor false)")
        else:
            state["error"] = "No active app authentication policy, and " + (signon_problem or "no global session policy")
            return state

        state["weak"] = weak
        state["enabled"] = strong > 0
        state["enforced"] = judged_rules > 0 and not weak
        state["summary"] = (engine + ": " + str(strong) + " of " + str(judged_rules) + " allowing sign-on rules require two factors across "
                            + str(len(app_policies) if app_policies else len(signon or [])) + " policies")
        state["inputSummary"] = {
            "engine": engine,
            "appPoliciesJudged": [as_text(p.get("name")) for (p, r) in app_policies],
            "policiesNotJudged": other_policies,
            "allowRules": judged_rules,
            "twoFactorRules": strong,
            "singleFactorRules": len(weak),
        }
        return state

    def respond(result, passes, fails, summary, errors):
        value = all(result.values())
        return {
            "transformedResponse": result,
            "additionalInfo": {
                "dataCollection": {"status": "success", "errors": []},
                "validation": {"status": "success" if not errors else "error", "errors": [], "warnings": []},
                "transformation": {"status": "error" if errors else "success", "errors": errors, "inputSummary": summary},
                "evaluation": {"passReasons": passes, "failReasons": fails, "recommendations": [] if value else
                               ["Require two factors (factorMode 2FA) on every rule that allows access in every Okta authentication policy"],
                               "additionalFindings": []},
                "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0",
                             "transformationId": "isMFAEnforcedForUsers", "vendor": "Okta", "category": "Identity"},
            },
        }

    return {"evaluate": evaluate, "respond": respond}
