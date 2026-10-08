# isstrongauthrequired.py - Okta (Identity Engine and Classic)
#
# Method: workflow getMfaPolicyRules (Integration-Service), the same four GETs ismfaenforcedforusers.py reads:
#   GET /api/v1/policies?type=OKTA_SIGN_ON        -> signOnPolicies   (global session policies)
#   GET /api/v1/policies/{policyId}/rules         -> signOnRules      (one list per policy, same order)
#   GET /api/v1/policies?type=ACCESS_POLICY       -> accessPolicies   (authentication policies)
#   GET /api/v1/policies/{policyId}/rules         -> accessRules      (one list per policy, same order)
# Docs: https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Policy/
#   listPolicies, listPolicyRules (scope okta.policies.read, already granted for isMFAEnforcedForUsers).
#   AccessPolicyRule.actions.appSignOn.{access, verificationMethod.{type, factorMode, constraints[]}}
#   verificationMethod.constraints[].possession.authenticationMethods[].{key, method}
#   OktaSignOnPolicyRule.actions.signon.{access, requireFactor}
#
# Replaces the generic safeguards/86ded564.../isstrongauthrequired.py for Okta. That file was wired to
# getEstateSecondFactors (GET /api/v1/org/factors), a catalogue of factor TYPES, not of policies, so on Okta it
# can only answer None. This file reads the policies and rules themselves.


def transform(input):
    """
    isStrongAuthRequired - True only when every path into an app demands a factor and none of those paths
    names a weak factor as an accepted way to satisfy it.

    Identity Engine (at least one ACTIVE app authentication policy, _embedded.resourceType APP or absent):
    every ACTIVE rule that ALLOWs access, in every ACTIVE app authentication policy, must
      * require a factor: verificationMethod type ASSURANCE with factorMode 2FA, and
      * not accept a weak factor: when the rule lists the authentication methods it accepts
        (constraints[].possession.authenticationMethods), none may be SMS or voice (key phone_number),
        email (key okta_email) or a security question (key security_question).
    Rule conditions (network zone, group, device) are ignored on purpose: a rule scoped to one zone that
    accepts one factor or a weak factor is still a weak path. Policies with resourceType
    END_USER_ACCOUNT_MANAGEMENT (enrolment, recovery, unlock) are not app sign-in and are reported, not judged.

    Classic Engine (the authentication policy list holds no active app policy): every ACTIVE rule that ALLOWs
    access in every ACTIVE global session (OKTA_SIGN_ON) policy must have requireFactor true. A Classic rule
    cannot name factors, so weak factors are not judged there.

    False when a readable rule accepts less than a factor or names a weak factor.
    None (Not evaluated, dataCollection.status "error"), never False, when the read cannot answer: an error
    body, a non-object body, missing or misaligned policy and rule lists, an active policy with no active
    rules, no rule that allows sign-on, a verification method this code does not read (AUTH_METHOD_CHAIN,
    ID_PROOFING, missing) when no readable rule already fails, and a transformation error.

    Does not prove: which authenticators the org has switched on (authTypesAllowed reads
    /api/v1/authenticators), a weak factor that a rule accepts without listing methods, that every user has
    enrolled a factor, or that the factors are phishing-resistant (isAdminMFAPhishingResistant,
    isPhishingResistantOnlyEnabled).
    """
    import json
    from datetime import datetime

    key = "isStrongAuthRequired"
    weak_keys = ["phone_number", "okta_email", "security_question"]
    weak_methods = ["sms", "voice", "call", "email", "security_question"]

    def as_text(value):
        if value is None:
            return ""
        return str(value).strip()

    def is_true(value):
        if isinstance(value, bool):
            return value
        return as_text(value).lower() == "true"

    def is_active(obj):
        return as_text(obj.get("status")).upper() == "ACTIVE"

    def respond(value, passes, fails, summary, errors):
        # None is decided by the value: Token-Service grades a None as Failed unless dataCollection.status is
        # "error", so a None always carries its reason as an error and a measured value never does.
        if value is None and not errors:
            errors = ["Not measured: " + key]
        return {
            "transformedResponse": {key: value},
            "additionalInfo": {
                "dataCollection": {"status": "error" if value is None else "success",
                                   "errors": errors if value is None else []},
                "validation": {"status": "success", "errors": [], "warnings": []},
                "transformation": {"status": "success", "errors": [], "inputSummary": summary},
                "evaluation": {"passReasons": passes, "failReasons": fails,
                               "recommendations": ["Require two factors (factorMode 2FA) on every rule that allows access "
                                                   "in every Okta authentication policy, and remove SMS, voice, email "
                                                   "and security question from the methods those rules accept"]
                               if value is False else [],
                               "additionalFindings": []},
                "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0",
                             "transformationId": key, "vendor": "Okta", "category": "Identity and Access Management"},
            },
        }

    def not_evaluated(reason, summary):
        return respond(None, [], ["Not evaluated: " + reason], summary, [reason])

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

    def resource_type(policy):
        embedded = policy.get("_embedded")
        if isinstance(embedded, dict):
            return as_text(embedded.get("resourceType")).upper()
        return ""

    def weak_names(method):
        """Weak authentication methods a rule lists as accepted (constraints[].possession/knowledge/inherence)."""
        names = []
        constraints = method.get("constraints")
        if not isinstance(constraints, list):
            return names
        for constraint in constraints:
            if not isinstance(constraint, dict):
                continue
            for family in ["possession", "knowledge", "inherence"]:
                block = constraint.get(family)
                listed = block.get("authenticationMethods") if isinstance(block, dict) else None
                if not isinstance(listed, list):
                    continue
                for entry in listed:
                    if not isinstance(entry, dict):
                        continue
                    entry_key = as_text(entry.get("key")).lower()
                    entry_method = as_text(entry.get("method")).lower()
                    if entry_key in weak_keys or entry_method in weak_methods:
                        names.append(entry_key + ("/" + entry_method if entry_method else ""))
        return names

    try:
        data = input
        if isinstance(data, bytes):
            data = data.decode("utf-8")
        if isinstance(data, str):
            data = json.loads(data)
        for wrapper in ["data", "response", "result", "apiResponse", "_response_data"]:
            if isinstance(data, dict) and wrapper in data and "accessPolicies" not in data and "signOnPolicies" not in data:
                data = data[wrapper]
        if not isinstance(data, dict):
            return not_evaluated("the response is not an object with policy and rule lists", {})
        for field in ["errorCode", "errorSummary", "error", "errors", "errorMessage"]:
            if data.get(field):
                return not_evaluated("Okta returned an error: " + as_text(data.get(field))[:200], {})

        access, access_problem = pair(data.get("accessPolicies"), data.get("accessRules"), "Authentication (ACCESS_POLICY)")
        signon, signon_problem = pair(data.get("signOnPolicies"), data.get("signOnRules"), "Global session (OKTA_SIGN_ON)")
        if access_problem is not None:
            return not_evaluated(access_problem, {})

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
        judged = 0
        if app_policies:
            engine = "Identity Engine"
            policy_count = len(app_policies)
            for policy, rules in app_policies:
                active_rules = [r for r in rules if is_active(r)]
                if not active_rules:
                    return not_evaluated("Authentication policy '" + as_text(policy.get("name")) + "' has no active rules", {})
                for rule in active_rules:
                    actions = rule.get("actions") if isinstance(rule.get("actions"), dict) else {}
                    sign_on = actions.get("appSignOn") if isinstance(actions.get("appSignOn"), dict) else {}
                    if as_text(sign_on.get("access")).upper() != "ALLOW":
                        continue
                    judged = judged + 1
                    method = sign_on.get("verificationMethod") if isinstance(sign_on.get("verificationMethod"), dict) else {}
                    method_type = as_text(method.get("type")).upper()
                    mode = as_text(method.get("factorMode")).upper()
                    where = as_text(policy.get("name")) + " / " + as_text(rule.get("name"))
                    if method_type == "ASSURANCE" and mode == "2FA":
                        names = weak_names(method)
                        if names:
                            weak.append(where + " (accepts " + ", ".join(names[:4]) + ")")
                        else:
                            strong = strong + 1
                    elif method_type == "ASSURANCE":
                        weak.append(where + " (factorMode " + (mode or "missing") + ")")
                    else:
                        unread.append(where + " (verification method " + (method_type or "missing") + ")")
        elif signon is not None:
            engine = "Classic Engine"
            active_policies = [(p, r) for (p, r) in signon if is_active(p)]
            policy_count = len(active_policies)
            if not active_policies:
                return not_evaluated("No active app authentication policy and no active global session policy was returned", {})
            for policy, rules in active_policies:
                active_rules = [r for r in rules if is_active(r)]
                if not active_rules:
                    return not_evaluated("Global session policy '" + as_text(policy.get("name")) + "' has no active rules", {})
                for rule in active_rules:
                    actions = rule.get("actions") if isinstance(rule.get("actions"), dict) else {}
                    sign_on = actions.get("signon") if isinstance(actions.get("signon"), dict) else {}
                    if as_text(sign_on.get("access")).upper() != "ALLOW":
                        continue
                    judged = judged + 1
                    where = as_text(policy.get("name")) + " / " + as_text(rule.get("name"))
                    if is_true(sign_on.get("requireFactor")):
                        strong = strong + 1
                    else:
                        weak.append(where + " (requireFactor false)")
        else:
            return not_evaluated("No active app authentication policy, and " + (signon_problem or "no global session policy"), {})

        summary = {"engine": engine, "policiesJudged": policy_count, "allowRules": judged, "strongRules": strong,
                   "weakRules": len(weak), "unreadRules": len(unread), "policiesNotJudged": other_policies}
        if judged == 0:
            return not_evaluated("No active rule allows sign-on, so there is no sign-in path to judge", summary)
        if weak:
            fails = ["Weak sign-in path: " + line for line in weak[:10]]
            return respond(False, [], fails, summary, [])
        if unread:
            return not_evaluated(str(len(unread)) + " allowing sign-on rule(s) use a verification method this check does not read: "
                                 + "; ".join(unread[:5]), summary)
        return respond(True, [engine + ": all " + str(judged) + " allowing sign-on rule(s) across " + str(policy_count)
                              + " policies require a factor and accept no listed weak factor"], [], summary, [])
    except Exception as e:
        return not_evaluated("Transformation error: " + str(e), {})
