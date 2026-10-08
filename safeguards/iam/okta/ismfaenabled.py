# ismfaenabled.py - Okta (Identity Engine and Classic)
#
# Answers isMFAEnabled on its own, from the same getMfaPolicyRules read as ismfaenforcedforusers.py (four GETs:
# OKTA_SIGN_ON policies and rules, ACCESS_POLICY policies and rules; scope okta.policies.read). Rule schemas:
#   AccessPolicyRule.actions.appSignOn.{access, verificationMethod.{type, factorMode}}
#   OktaSignOnPolicyRule.actions.signon.{access, requireFactor}
# Docs: https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Policy/
#
# WHY A FILE OF ITS OWN. Token-Service decides "not evaluated" from dataCollection.status, which belongs to the
# whole output, and a transform is not told which key it is answering. In ismfaenforcedforusers.py one output
# carries both keys, so a rule it cannot read (AUTH_METHOD_CHAIN) leaves isMFAEnforcedForUsers unmeasured and
# takes isMFAEnabled down with it, even where a readable rule already proves two factors. Here the key stands
# alone, so what it says depends only on what proves it.
#
# The rule reading below is kept identical to ismfaenforcedforusers.py; test_okta_ismfaenabled.py runs both files
# on the same bodies and fails if they ever disagree about which rules require two factors.

def transform(input):
    """
    isMFAEnabled: True when at least one ACTIVE rule that ALLOWs sign-on requires two factors.

    Identity Engine (at least one ACTIVE authentication policy whose _embedded.resourceType is APP or absent):
    a rule counts when its verificationMethod is type ASSURANCE with factorMode 2FA. Classic Engine (the
    authentication policy list is readable but holds no active app policy): a rule counts when requireFactor
    is true in an ACTIVE global session policy.

    One rule that requires two factors proves MFA is enabled, so the answer stays True beside rules this code
    cannot read (AUTH_METHOD_CHAIN, ID_PROOFING, missing) and beside rules that accept one factor: those say
    something about enforcement, which is isMFAEnforcedForUsers' question, and nothing about whether MFA is
    enabled. False is reported only when every allowing rule was read and none requires two factors.

    Not measured (None, dataCollection.status "error"): an error body, missing policy or rule lists, a rule list
    whose length does not match its policy list, an active policy with no active rules, no rule that allows
    sign-on, a transformation error, and the one case where no readable rule requires two factors while some
    rule could not be read, so a two-factor rule may be among them.

    A remediation is recommended only for a measured False.

    Does not prove: that MFA is enforced on every path (see isMFAEnforcedForUsers), which authenticators can
    satisfy the second factor (see authTypesAllowed), or that every user has enrolled one.
    """
    key = "isMFAEnabled"
    checks = MFA_CHECKS()
    try:
        state = checks["evaluate"](input)
    except Exception as e:
        reason = "Transformation error: " + str(e)
        return checks["respond"]({key: None}, [], [reason], {}, [str(e)], [reason])
    if state["error"] is not None:
        return checks["respond"]({key: None}, [], [state["error"]], state["inputSummary"], [], [state["error"]])
    enabled = state["enabled"]
    passes = []
    fails = []
    not_measured = []
    if enabled is True:
        passes.append(state["summary"])
        if state["unread"]:
            passes.append(str(len(state["unread"])) + " allowing sign-on rule(s) use a verification method this check "
                          "does not read; they do not change this answer: " + "; ".join(state["unread"][:5]))
    elif enabled is False:
        fails.append(state["summary"])
        for weak in state["weak"][:10]:
            fails.append("Single-factor path: " + weak)
    else:
        for unread in state["unread"][:10]:
            fails.append("Not evaluated: " + unread)
        not_measured.append("No readable allowing sign-on rule requires two factors, and " + str(len(state["unread"]))
                            + " allowing rule(s) use a verification method this check does not read: "
                            + "; ".join(state["unread"][:5]))
    return checks["respond"]({key: enabled}, passes, fails, state["inputSummary"], [], not_measured)


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
        state = {"error": None, "enforced": None, "enabled": None, "weak": [], "unread": [], "summary": "",
                 "inputSummary": {}}
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
        unread = []
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
                        unread.append(where + " (verification method " + (method_type or "missing") + ")")
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

        if judged_rules == 0:
            state["error"] = "No active rule allows sign-on, so there is no sign-in path to judge"
            return state
        state["weak"] = weak
        state["unread"] = unread
        # A rule this code cannot read is neither evidence of two factors nor of one.
        if strong > 0:
            state["enabled"] = True
        elif not unread:
            state["enabled"] = False
        if weak:
            state["enforced"] = False
        elif not unread:
            state["enforced"] = True
        state["summary"] = (engine + ": " + str(strong) + " of " + str(judged_rules) + " allowing sign-on rules require two factors across "
                            + str(len(app_policies) if app_policies else len(signon or [])) + " policies")
        state["inputSummary"] = {
            "engine": engine,
            "appPoliciesJudged": [as_text(p.get("name")) for (p, r) in app_policies],
            "policiesNotJudged": other_policies,
            "allowRules": judged_rules,
            "twoFactorRules": strong,
            "singleFactorRules": len(weak),
            "unreadRules": len(unread),
        }
        return state

    def respond(result, passes, fails, summary, errors, api_errors):
        # Not measured is decided by the value, in both directions: no path returns None under a "success"
        # status, and no path returns a value under an "error" status.
        unmeasured = [k for k in result if result[k] is None]
        failed = [k for k in result if result[k] is False]
        if unmeasured and not api_errors:
            api_errors = ["Not measured: " + ", ".join(unmeasured)]
        return {
            "transformedResponse": result,
            "additionalInfo": {
                "dataCollection": {"status": "error" if unmeasured else "success",
                                   "errors": api_errors if unmeasured else []},
                "validation": {"status": "success" if not errors else "error", "errors": [], "warnings": []},
                "transformation": {"status": "error" if errors else "success", "errors": errors, "inputSummary": summary},
                "evaluation": {"passReasons": passes, "failReasons": fails, "recommendations":
                               ["Require two factors (factorMode 2FA) on the rules that allow access in your Okta authentication policies"]
                               if failed else [], "additionalFindings": []},
                "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0",
                             "transformationId": "isMFAEnabled", "vendor": "Okta", "category": "Identity"},
            },
        }

    return {"evaluate": evaluate, "respond": respond}
