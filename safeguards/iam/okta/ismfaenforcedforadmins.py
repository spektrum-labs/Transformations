# ismfaenforcedforadmins.py - Okta Identity Engine
#
# Method: workflow getMfaPolicyRules (Integration-Service), the same four GETs ismfaenforcedforusers.py
# reads; only two are used here:
#   GET /api/v1/policies?type=ACCESS_POLICY       -> accessPolicies   (app authentication policies)
#   GET /api/v1/policies/{policyId}/rules         -> accessRules      (one list per policy, same order)
# Docs: https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Policy/
#   listPolicies, listPolicyRules (scope okta.policies.read, already granted for isMFAEnforcedForUsers).
#   AccessPolicyRule.actions.appSignOn.{access, verificationMethod.{type, factorMode}}
#
# Why the Admin Console policy: every Okta administrator signs in to the Okta Admin Console (app
# "saasure"), and Identity Engine gates that app with its own authentication policy, which Okta
# creates as "Okta Admin Console". Measured in Spektrum's tenant 2026-09-25 (Integration-Service
# run_with_override, GETs only): ACCESS_POLICY "Okta Admin Console" with rules "Admin App Policy" and
# "Catch-all Rule", both ALLOW / ASSURANCE / factorMode 2FA. Reading admin role assignments instead
# needs okta.roles.read, which the service app is not granted (401 measured the same day).


def transform(input):
    """
    isMFAEnforcedForAdmins - True only when the ACTIVE "Okta Admin Console" authentication policy exists,
    has at least one ACTIVE rule that ALLOWs access, and every ACTIVE ALLOW rule in it requires
    verificationMethod type ASSURANCE with factorMode 2FA. Rule conditions (zone, group, device) are
    ignored on purpose: a 1FA rule scoped to one network is still a single-factor path into the console.

    Also returns adminConsoleAllowRules (ALLOW rules judged) and adminConsoleSingleFactorRules (those
    that do not demand two factors), as numbers.

    Fails closed on: an error body, missing or misaligned policy/rule lists, no ACTIVE policy of that
    name (a Classic Engine org, or a renamed policy: not measured here, so not passed), a policy with
    no active ALLOW rule, and any verification method this code does not recognise.

    Does not prove: which authenticators satisfy the second factor, or anything about other admin
    surfaces (API tokens, Okta Privileged Access).
    """
    import json
    from datetime import datetime

    key = "isMFAEnforcedForAdmins"
    policy_name = "okta admin console"

    def as_text(value):
        if value is None:
            return ""
        return str(value).strip()

    def respond(value, allow_rules, weak_rules, passes, fails, summary, errors):
        return {
            "transformedResponse": {key: value, "adminConsoleAllowRules": allow_rules,
                                    "adminConsoleSingleFactorRules": weak_rules},
            "additionalInfo": {
                "dataCollection": {"status": "error" if errors else "success", "errors": errors},
                "validation": {"status": "unknown", "errors": [], "warnings": []},
                "transformation": {"status": "error" if errors else "success", "errors": errors, "inputSummary": summary},
                "evaluation": {"passReasons": passes, "failReasons": fails, "recommendations": [], "additionalFindings": []},
                "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0",
                             "transformationId": key, "vendor": "Okta", "category": "Identity and Access Management"},
            },
        }

    def fail(reason):
        return respond(False, 0, 0, [], [reason], {}, [reason])

    try:
        data = input
        if isinstance(data, bytes):
            data = data.decode("utf-8")
        if isinstance(data, str):
            data = json.loads(data)
        for wrapper in ["data", "response", "result", "apiResponse", "_response_data"]:
            if isinstance(data, dict) and wrapper in data and "accessPolicies" not in data:
                data = data[wrapper]
        if not isinstance(data, dict):
            return fail("Response is not an object with policy and rule lists")
        for k in ["errorCode", "errorSummary", "error", "errors", "errorMessage"]:
            if data.get(k):
                return fail("Okta returned an error: " + as_text(data.get(k))[:200])

        policies = data.get("accessPolicies")
        rules = data.get("accessRules")
        if not isinstance(policies, list):
            return fail("Authentication (ACCESS_POLICY) policy list is missing")
        if not isinstance(rules, list) or len(rules) != len(policies):
            return fail("Authentication policy rule lists are missing or do not line up with the policies")

        found = None
        for index in range(len(policies)):
            policy = policies[index]
            if not isinstance(policy, dict):
                continue
            if as_text(policy.get("name")).lower() == policy_name and as_text(policy.get("status")).upper() == "ACTIVE":
                found = (policy, rules[index])
                break
        if found is None:
            return fail("No ACTIVE 'Okta Admin Console' authentication policy was returned (Classic Engine or renamed policy): admin MFA not measured")

        policy, policy_rules = found
        while isinstance(policy_rules, dict):
            inner = None
            for wrapper in ["apiResponse", "response", "result"]:
                if wrapper in policy_rules:
                    inner = policy_rules[wrapper]
                    break
            if inner is None:
                break
            policy_rules = inner
        if not isinstance(policy_rules, list):
            return fail("Rules for the 'Okta Admin Console' policy are unreadable")

        allow = 0
        weak = []
        for rule in policy_rules:
            if not isinstance(rule, dict) or as_text(rule.get("status")).upper() != "ACTIVE":
                continue
            actions = rule.get("actions") if isinstance(rule.get("actions"), dict) else {}
            sign_on = actions.get("appSignOn") if isinstance(actions.get("appSignOn"), dict) else {}
            if as_text(sign_on.get("access")).upper() != "ALLOW":
                continue
            allow = allow + 1
            method = sign_on.get("verificationMethod") if isinstance(sign_on.get("verificationMethod"), dict) else {}
            method_type = as_text(method.get("type")).upper()
            mode = as_text(method.get("factorMode")).upper()
            if not (method_type == "ASSURANCE" and mode == "2FA"):
                weak.append(as_text(rule.get("name")) + " (" + (method_type or "no method") + " / " + (mode or "no factorMode") + ")")

        summary = {"policy": as_text(policy.get("name")), "allowRules": allow, "singleFactorRules": len(weak)}
        if allow == 0:
            return respond(False, 0, 0, [], ["The 'Okta Admin Console' policy has no active rule that allows access"], summary, [])
        if weak:
            return respond(False, allow, len(weak), [],
                           ["Admin Console sign-in accepts less than two factors: " + ", ".join(weak[:10])], summary, [])
        return respond(True, allow, 0,
                       ["All " + str(allow) + " active ALLOW rule(s) of the 'Okta Admin Console' policy require two factors"],
                       [], summary, [])
    except Exception as e:
        return fail("Transformation error: " + str(e))
