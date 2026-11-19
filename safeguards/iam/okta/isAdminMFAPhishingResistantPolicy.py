"""
Transformation: isAdminMFAPhishingResistant (Admin Console policy)
Vendor: Okta   Method: workflow isAdminMFAPhishingResistant (the Okta Admin Console app's authentication policy)

Requirement asked: "Only phishing-resistant factors for admins are permitted." Judged from what admins are actually
held to when they sign in to the Okta Admin Console, not from which factors the org could enroll (the older file
isAdminMFAPhishingResistant.py, left unchanged for pins that still use it).

The workflow reads:
  applications   the Okta Admin Console is the app named "saasure"; its _links.accessPolicy.href names its
                 authentication policy. Either GET /api/v1/apps?limit=200 (okta.apps.read) or the single-app read
                 GET /api/v1/apps?filter=name%20eq%20%22saasure%22 works: the app is found by name in the list.
  accessPolicies GET /api/v1/policies?type=ACCESS_POLICY (okta.policies.read)
  accessRules    GET /api/v1/policies/{policyId}/rules, one list per policy, same order
Docs: https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Policy/
  AccessPolicyRule.actions.appSignOn.verificationMethod: ASSURANCE {factorMode, constraints[] (alternatives, each
  {knowledge, possession: {required, phishingResistant, userVerification}})} or AUTH_METHOD_CHAIN {chains[] of
  {authenticationMethods[] {key, method, phishingResistant, userVerification}, next[]}}.

Verdict: True only when every ACTIVE ALLOW rule of the Admin Console policy demands a phishing-resistant
authenticator on every way in, as part of two factor types:
  ASSURANCE: every constraint requires possession with phishingResistant REQUIRED, and factorMode is 2FA or that
    possession also requires userVerification (a FIDO2 key or FastPass with biometrics/PIN is two factors).
  AUTH_METHOD_CHAIN: every path proves two factor types and has a step whose every alternative is phishing
    resistant (phishingResistant REQUIRED, or a webauthn / smart_card_idp authenticator).
False when a readable ALLOW rule lets an admin in without that. None (not evaluated) when the Admin Console app is not in
the app list (errorCode not_available: Okta hides it from an OAuth service app, so the check routes to product; a list
cut short at the 200-app limit is uncoded), its policy is not found, the policy's rule list has no system Catch-all Rule (cut
short), no rule allows sign-in, or a rule's verification method cannot be read and no rule already fails.

Output: every return carries {isAdminMFAPhishingResistant, phishingResistantRules, weakRules}; the two counts are
None when not evaluated, so a threshold token never meets a missing key.
"""
import json
from datetime import datetime

KEY = "isAdminMFAPhishingResistant"
ADMIN_CONSOLE_APP = "saasure"
APP_LIST_LIMIT = 200  # the workflow reads GET /api/v1/apps?limit=200
POLICY_PR_KEYS = ["webauthn", "smart_card_idp"]
# The factor tables below are the same as in ismfaenforcedforusers.py and isstrongauthrequired.py (the sandbox
# forbids shared imports); test_okta_auth_method_chain_parity.py keeps the three copies in line.
KNOWLEDGE_KEYS = ["okta_password", "security_question"]
KNOWLEDGE_METHODS = ["password", "security_question"]
POSSESSION_KEYS = ["okta_verify", "phone_number", "okta_email", "google_otp", "webauthn", "security_key",
                   "yubikey_token", "rsa_token", "symantec_vip", "duo", "custom_otp", "custom_app", "smart_card_idp",
                   "onprem_mfa"]
POSSESSION_METHODS = ["push", "totp", "signed_nonce", "sms", "voice", "email", "otp", "webauthn", "cert"]
CHAIN_MAX_STEPS = 5


def policy_text(value):
    return "" if value is None else str(value).strip()


def policy_dict(value):
    return value if isinstance(value, dict) else {}


def policy_list(value):
    for wrapper in ["apiResponse", "response", "result", "value"]:
        if isinstance(value, dict) and wrapper in value:
            value = value[wrapper]
    return [x for x in value if isinstance(x, dict)] if isinstance(value, list) else None


def extract_input(input_data):
    data = input_data
    if isinstance(data, bytes):
        data = data.decode("utf-8")
    if isinstance(data, str):
        data = json.loads(data)
    if isinstance(data, dict) and "data" in data and "validation" in data:
        data = data["data"]
    for _ in range(3):
        if isinstance(data, dict) and "accessPolicies" not in data:
            for key in ["api_response", "response", "result", "apiResponse", "Output"]:
                if isinstance(data.get(key), dict):
                    data = data[key]
                    break
    return data


def respond(value, passes, fails, summary, recommendations, strong, weak, error_code=None):
    collection = {"status": "error" if value is None else "success", "errors": fails if value is None else []}
    if error_code:
        collection["errorCode"] = error_code
    return {
        "transformedResponse": {KEY: value, "phishingResistantRules": strong, "weakRules": weak},
        "additionalInfo": {
            "dataCollection": collection,
            "validation": {"status": "success", "errors": [], "warnings": []},
            "transformation": {"status": "success", "errors": [], "inputSummary": summary},
            "evaluation": {"passReasons": passes, "failReasons": fails, "recommendations": recommendations,
                           "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "2.0",
                         "transformationId": KEY, "vendor": "Okta", "category": "iam"},
        },
    }


def unevaluated(message, summary=None, error_code=None):
    return respond(None, [], [message], summary or {}, [], None, None, error_code)


def assurance_resistant(method):
    """(True, "") when an ASSURANCE rule demands phishing-resistant MFA, else (False, why)."""
    constraints = method.get("constraints")
    if not isinstance(constraints, list) or not constraints:
        return False, "no authenticator constraint, so any enrolled factor satisfies it"
    two_factor = policy_text(method.get("factorMode")).upper() == "2FA"
    for constraint in constraints:
        possession = policy_dict(policy_dict(constraint).get("possession"))
        if policy_text(possession.get("phishingResistant")).upper() != "REQUIRED" or policy_text(possession.get("required")).lower() == "false":
            return False, "a constraint does not require a phishing-resistant authenticator"
        if not two_factor and policy_text(possession.get("userVerification")).upper() != "REQUIRED":
            return False, "factorMode " + (policy_text(method.get("factorMode")) or "missing") + " without user verification"
    return True, ""


def entry_types(entry):
    """Factor types one chain alternative proves, or None when its authenticator is not known."""
    key = policy_text(entry.get("key")).lower()
    method = policy_text(entry.get("method")).lower()
    if key == "smart_card_idp":
        return ["possession", "knowledge"]  # assumption: PIV/CAC = card plus PIN; the middleware enforces the PIN, the policy body cannot show it (Okta smart card IdP docs)
    if key in KNOWLEDGE_KEYS or method in KNOWLEDGE_METHODS:
        return ["knowledge"]
    if key in POSSESSION_KEYS or method in POSSESSION_METHODS:
        if policy_text(entry.get("userVerification")).upper() == "REQUIRED":
            return ["possession", "inherence"]
        return ["possession"]
    return None


def chain_resistant(method):
    """(True|False, why) for an AUTH_METHOD_CHAIN rule, or None when the chain cannot be read."""
    chains = method.get("chains")
    if not isinstance(chains, list) or not chains:
        return None
    stack = [(node, [()], False, 1) for node in chains]
    while stack:
        node, before, resistant, depth = stack.pop()
        if not isinstance(node, dict) or depth > CHAIN_MAX_STEPS:
            return None
        options = node.get("authenticationMethods")
        if not isinstance(options, list) or not options:
            return None
        merged = []
        step_resistant = True
        for option in options:
            option = policy_dict(option)
            types = entry_types(option)
            if types is None:
                return None
            if not (policy_text(option.get("key")).lower() in POLICY_PR_KEYS
                    or policy_text(option.get("phishingResistant")).upper() == "REQUIRED"):
                step_resistant = False
            for union in before:
                joined = tuple(sorted(set(list(union) + types)))
                if joined not in merged:
                    merged.append(joined)
        resistant = resistant or step_resistant
        following = node.get("next")
        if following is None or following == []:
            if not resistant:
                return False, "a way through the chain uses no phishing-resistant authenticator"
            if min([len(u) for u in merged]) < 2:
                return False, "a way through the chain proves one factor type"
        elif isinstance(following, list):
            for child in following:
                stack.append((child, merged, resistant, depth + 1))
        else:
            return None
    return True, ""


def evaluate(data):
    """The verdict from the Okta Admin Console authentication policy (see the module docstring)."""
    for field in ["errorCode", "errorSummary", "error", "errorMessage"]:
        if data.get(field):
            return unevaluated("Okta returned an error: " + policy_text(data.get(field))[:200])
    apps = policy_list(data.get("applications"))
    if apps is None:
        return unevaluated("The Okta app list (GET /api/v1/apps) was not read, so the Admin "
                                                "Console's authentication policy cannot be found.")
    console = [a for a in apps if policy_text(a.get("name")).lower() == ADMIN_CONSOLE_APP]
    if not console:
        if len(apps) >= APP_LIST_LIMIT:
            return unevaluated("The Okta app list was cut short at " + str(APP_LIST_LIMIT) + " apps and does not "
                               "include the Admin Console app, so the policy admins sign in under cannot be read.")
        # Okta hides the Admin Console app from an OAuth service app, even by an exact name filter; the connection
        # cannot read it, which is a vendor limit (routes to product), not a defect to engineer around.
        return unevaluated("NOT-AVAILABLE: Okta does not expose the Admin Console app's sign-in policy to this "
                           "connection (Okta hides the Admin Console app from an OAuth service app), so the policy "
                           "admins sign in under cannot be read.", None, "not_available")
    href = policy_text(policy_dict(policy_dict(console[0].get("_links")).get("accessPolicy")).get("href"))
    policy_id = href.split("?")[0].rstrip("/").split("/policies/")[1].split("/")[0] if "/policies/" in href else ""
    if not policy_id:
        return unevaluated("The Okta Admin Console app carries no authentication policy link "
                                                "(_links.accessPolicy).")
    policies = data.get("accessPolicies")
    rules = data.get("accessRules")
    if not isinstance(policies, list) or not isinstance(rules, list) or len(policies) != len(rules):
        return unevaluated("Okta authentication policy or rule lists are missing or do not line "
                                                "up with each other.")
    found = [i for i in range(len(policies)) if policy_text(policy_dict(policies[i]).get("id")) == policy_id]
    if len(found) != 1:
        return unevaluated("The Okta Admin Console's authentication policy was not returned "
                                                "exactly once in the authentication policy list.")
    policy = policies[found[0]]
    name = policy_text(policy.get("name"))
    rule_rows = policy_list(rules[found[0]])
    if policy_text(policy.get("status")).upper() != "ACTIVE":
        return unevaluated("The Okta Admin Console's authentication policy '" + name + "' is not "
                                                "ACTIVE.")
    if not rule_rows or not [r for r in rule_rows if r.get("system") is True or policy_text(r.get("system")).lower() == "true"]:
        return unevaluated("The rules of the Okta Admin Console policy '" + name + "' do not "
                                                "include its Catch-all Rule (always last), so the list is incomplete.")
    weak, unread, strong = [], [], 0
    for rule in rule_rows:
        if policy_text(rule.get("status")).upper() != "ACTIVE":
            continue
        sign_on = policy_dict(policy_dict(rule.get("actions")).get("appSignOn"))
        if policy_text(sign_on.get("access")).upper() != "ALLOW":
            continue
        where = name + " / " + policy_text(rule.get("name"))
        method = policy_dict(sign_on.get("verificationMethod"))
        kind = policy_text(method.get("type")).upper()
        verdict = None
        if kind == "ASSURANCE":
            verdict = assurance_resistant(method)
        elif kind == "AUTH_METHOD_CHAIN":
            verdict = chain_resistant(method)
        if verdict is None:
            unread.append(where + " (verification method " + (kind or "missing") + " not read)")
        elif verdict[0]:
            strong = strong + 1
        else:
            weak.append(where + " (" + verdict[1] + ")")
    summary = {"adminConsolePolicy": name, "allowRules": strong + len(weak) + len(unread),
               "phishingResistantRules": strong, "weakRules": len(weak), "unreadRules": len(unread)}
    if weak:
        return respond(False, [], ["Okta Admin Console sign-in does not require phishing-resistant MFA: " + w
                                   for w in weak[:10]], summary,
                       ["In the Okta Admin Console authentication policy, require a phishing-resistant "
                        "authenticator (possession: phishing resistant) on every rule that allows access."],
                       strong, len(weak))
    if unread or not strong:
        return unevaluated(("No rule of the Okta Admin Console policy '" + name + "' allows sign-in."
                            if not strong and not unread else
                            str(len(unread)) + " Admin Console rule(s) cannot be judged: " + "; ".join(unread[:5])),
                           summary)
    return respond(True, ["Okta Admin Console policy '" + name + "': all " + str(strong) + " rule(s) that allow "
                          "sign-in require a phishing-resistant authenticator as part of MFA."], [], summary, [],
                   strong, 0)


def transform(input):
    try:
        data = extract_input(input)
        if not isinstance(data, dict):
            return unevaluated("The response is not an object with the Okta app, policy and rule lists")
        return evaluate(data)
    except Exception as e:
        return unevaluated("Transformation error: " + str(e))
