"""isStrongAuthRequired for Okta reads getMfaPolicyRules (sign-on and authentication policies and rules).

Fixtures are synthetic. REAL_PASS and REAL_FALSE copy the SHAPE of an Identity Engine read (policy list,
one rule list per policy in the same order, ASSURANCE verification methods with factorMode and constraints),
with made-up names and ids.
"""
import copy
import importlib.util
import json
import unittest
from pathlib import Path

PATH = Path(__file__).with_name("isstrongauthrequired.py")
KEY = "isStrongAuthRequired"
ROOT = PATH.resolve().parents[3]


def load():
    spec = importlib.util.spec_from_file_location("okta_isstrongauthrequired", PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SandboxModule:
    """The same file compiled as Token-Service runs it (RestrictedPython replica in tools/)."""

    def __init__(self):
        spec = importlib.util.spec_from_file_location("restricted_sandbox_okta_strong", ROOT / "tools" / "restricted_sandbox.py")
        sandbox = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(sandbox)
        self.transform = sandbox.load(PATH.read_text(), "<transformation>")["transform"]


def rule(name, mode="2FA", access="ALLOW", status="ACTIVE", kind="ASSURANCE", methods=None):
    method = {"type": kind, "factorMode": mode, "reauthenticateIn": "PT12H",
              "constraints": [{"knowledge": {"required": True, "types": ["password"]}}]}
    if methods is not None:
        # One constraint object holds both families (Okta ORs separate constraint objects).
        method["constraints"][0]["possession"] = {"required": True, "authenticationMethods": methods}
    return {"id": "rul-" + name, "name": name, "status": status,
            "actions": {"appSignOn": {"access": access, "verificationMethod": method}}}


def app_policy(name, status="ACTIVE"):
    return {"id": "pol-" + name, "name": name, "type": "ACCESS_POLICY", "status": status, "_embedded": {"resourceType": "APP"}}


ACCOUNT_POLICY = {"id": "pol-acct", "name": "Account Management", "type": "ACCESS_POLICY", "status": "ACTIVE",
                  "_embedded": {"resourceType": "END_USER_ACCOUNT_MANAGEMENT"}}
STRONG_METHODS = [{"key": "okta_verify", "method": "push"}, {"key": "webauthn", "method": "webauthn"}]
# /api/v1/authenticators shape (key, status, settings.allowedFor); synthetic values.
STRONG_AUTHENTICATORS = [
    {"key": "okta_password", "status": "ACTIVE"},
    {"key": "okta_verify", "status": "ACTIVE"},
    {"key": "webauthn", "status": "ACTIVE"},
    {"key": "okta_email", "status": "ACTIVE", "settings": {"allowedFor": "recovery"}},
    {"key": "phone_number", "status": "INACTIVE"},
]

REAL_PASS = {"result": {
    "signOnPolicies": [{"id": "pol-so", "name": "Global Session", "type": "OKTA_SIGN_ON", "status": "ACTIVE"}],
    "signOnRules": [[{"name": "Default", "status": "ACTIVE",
                      "actions": {"signon": {"access": "ALLOW", "requireFactor": False, "primaryFactor": "PASSWORD_IDP_ANY_FACTOR"}}}]],
    "authenticators": STRONG_AUTHENTICATORS,
    "accessPolicies": [app_policy("Console"), app_policy("Apps"), app_policy("Strong Apps"), ACCOUNT_POLICY],
    "accessRules": [
        [rule("Admin"), rule("Catch-all")],
        [rule("Default")],
        [rule("Hardware", methods=STRONG_METHODS), rule("Blocked", mode="1FA", access="DENY")],
        [rule("Recovery", mode="1FA"), rule("Unlock", mode="2FA_If_Possible")],
    ],
}}

REAL_FALSE = copy.deepcopy(REAL_PASS)
REAL_FALSE["result"]["accessRules"][1] = [rule("Default", mode="1FA")]

FACTOR_CATALOGUE = [
    {"factorType": "sms", "provider": "EXAMPLE", "status": "ACTIVE"},
    {"factorType": "token:software:totp", "provider": "EXAMPLE", "status": "ACTIVE"},
]

CLASSIC = {"signOnPolicies": [{"id": "pol-so", "name": "Global Session", "status": "ACTIVE"}],
           "signOnRules": [[{"name": "Rule A", "status": "ACTIVE", "actions": {"signon": {"access": "ALLOW", "requireFactor": True}}},
                            {"name": "Rule B", "status": "INACTIVE", "actions": {"signon": {"access": "ALLOW", "requireFactor": False}}},
                            {"name": "Rule C", "status": "ACTIVE", "actions": {"signon": {"access": "DENY", "requireFactor": False}}}]],
           "accessPolicies": [], "accessRules": [],
           "factors": [{"factorType": "token:software:totp", "provider": "EXAMPLE", "status": "ACTIVE"},
                       {"factorType": "push", "provider": "EXAMPLE", "status": "ACTIVE"},
                       {"factorType": "sms", "provider": "EXAMPLE", "status": "INACTIVE"}]}


class StrongAuthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.transforms = [load().transform, SandboxModule().transform]

    def each(self, payload):
        for transform in self.transforms:
            yield transform(copy.deepcopy(payload))

    def assert_value(self, payload, expected):
        for out in self.each(payload):
            self.assertEqual(list(out["transformedResponse"]), [KEY])
            self.assertIs(out["transformedResponse"][KEY], expected)
            collection = out["additionalInfo"]["dataCollection"]
            if expected is None:
                self.assertEqual(collection["status"], "error")
                self.assertTrue(collection["errors"])
                self.assertEqual(out["additionalInfo"]["evaluation"]["recommendations"], [])
            else:
                self.assertEqual(collection["status"], "success")
                self.assertEqual(collection["errors"], [])

    # --- measured ---------------------------------------------------------------------------

    def test_real_shape_passes(self):
        self.assert_value(REAL_PASS, True)
        out = load().transform(REAL_PASS)
        summary = out["additionalInfo"]["transformation"]["inputSummary"]
        self.assertEqual(summary["allowRules"], 4)
        self.assertEqual(summary["strongRules"], 4)
        self.assertEqual(summary["weakRules"], 0)
        self.assertEqual(summary["policiesNotJudged"], ["Account Management (END_USER_ACCOUNT_MANAGEMENT)"])

    def test_real_shape_with_one_single_factor_rule_is_false(self):
        self.assert_value(REAL_FALSE, False)
        out = load().transform(REAL_FALSE)
        self.assertIn("Apps / Default (factorMode 1FA)", out["additionalInfo"]["evaluation"]["failReasons"][0])
        self.assertTrue(out["additionalInfo"]["evaluation"]["recommendations"])

    def test_two_factors_if_possible_is_false(self):
        payload = copy.deepcopy(REAL_PASS)
        payload["result"]["accessRules"][1] = [rule("Default", mode="2FA_If_Possible")]
        self.assert_value(payload, False)

    def test_missing_factor_mode_is_false(self):
        payload = copy.deepcopy(REAL_PASS)
        payload["result"]["accessRules"][1] = [rule("Default", mode="")]
        self.assert_value(payload, False)

    def test_rule_that_lists_a_weak_factor_is_false(self):
        for weak in ({"key": "phone_number", "method": "sms"}, {"key": "phone_number", "method": "voice"},
                     {"key": "okta_email", "method": "email"}, {"key": "security_question", "method": "security_question"}):
            payload = copy.deepcopy(REAL_PASS)
            payload["result"]["accessRules"][1] = [rule("Default", methods=STRONG_METHODS + [weak])]
            self.assert_value(payload, False)
            out = load().transform(payload)
            self.assertIn("accepts " + weak["key"], out["additionalInfo"]["evaluation"]["failReasons"][0])

    def test_rule_listing_only_strong_factors_passes(self):
        payload = copy.deepcopy(REAL_PASS)
        payload["result"]["accessRules"][1] = [rule("Default", methods=STRONG_METHODS)]
        self.assert_value(payload, True)

    def test_inactive_and_deny_rules_and_policies_are_ignored(self):
        payload = copy.deepcopy(REAL_PASS)
        payload["result"]["accessPolicies"].append(app_policy("Old", status="INACTIVE"))
        payload["result"]["accessRules"].append([rule("Legacy", mode="1FA")])
        payload["result"]["accessRules"][0].append(rule("Retired", mode="1FA", status="INACTIVE"))
        payload["result"]["accessRules"][0].append(rule("Refuse", mode="1FA", access="DENY"))
        self.assert_value(payload, True)

    def test_accepted_input_wrappers(self):
        bare = REAL_PASS["result"]
        self.assert_value(bare, True)
        self.assert_value({"apiResponse": bare}, True)
        self.assert_value(json.dumps(REAL_PASS), True)
        self.assert_value(json.dumps(REAL_FALSE).encode("utf-8"), False)
        wrapped = copy.deepcopy(bare)
        wrapped["accessRules"] = [{"apiResponse": rules} for rules in wrapped["accessRules"]]
        self.assert_value(wrapped, True)

    def test_classic_engine_reads_require_factor(self):
        self.assert_value(CLASSIC, True)
        failing = copy.deepcopy(CLASSIC)
        failing["signOnRules"][0][0]["actions"]["signon"]["requireFactor"] = False
        self.assert_value(failing, False)
        text = copy.deepcopy(CLASSIC)
        text["signOnRules"][0][0]["actions"]["signon"]["requireFactor"] = "false"
        self.assert_value(text, False)

    def test_weak_rule_beside_an_unreadable_rule_is_false(self):
        payload = copy.deepcopy(REAL_PASS)
        payload["result"]["accessRules"][1] = [rule("Default", mode="1FA"), rule("Chain", kind="AUTH_METHOD_CHAIN")]
        self.assert_value(payload, False)

    def test_rule_without_listed_methods_and_a_weak_authenticator_on_is_false(self):
        for weak in ({"key": "phone_number", "status": "ACTIVE"}, {"key": "security_question", "status": "ACTIVE"},
                     {"key": "okta_email", "status": "ACTIVE", "settings": {"allowedFor": "any"}}):
            payload = copy.deepcopy(REAL_PASS)
            payload["result"]["authenticators"] = STRONG_AUTHENTICATORS + [weak]
            self.assert_value(payload, False)
            out = load().transform(payload)
            self.assertIn("weak authenticators are on: " + weak["key"], out["additionalInfo"]["evaluation"]["failReasons"][0])

    def test_rule_listing_only_strong_methods_passes_even_with_a_weak_authenticator_on(self):
        payload = copy.deepcopy(REAL_PASS)
        payload["result"]["accessRules"] = [[rule("Admin", methods=STRONG_METHODS)], [rule("Default", methods=STRONG_METHODS)],
                                            [rule("Hardware", methods=STRONG_METHODS)], []]
        payload["result"]["authenticators"] = STRONG_AUTHENTICATORS + [{"key": "phone_number", "status": "ACTIVE"}]
        self.assert_value(payload, True)

    def test_classic_require_factor_with_a_weak_factor_on_is_false(self):
        for factor_type in ("sms", "call", "email", "question"):
            payload = copy.deepcopy(CLASSIC)
            payload["factors"].append({"factorType": factor_type, "provider": "EXAMPLE", "status": "ACTIVE"})
            self.assert_value(payload, False)
            out = load().transform(payload)
            self.assertIn("weak factors are on: " + factor_type, out["additionalInfo"]["evaluation"]["failReasons"][0])

    def test_classic_uses_the_authenticator_list_when_it_has_no_factor_list(self):
        payload = copy.deepcopy(CLASSIC)
        del payload["factors"]
        payload["authenticators"] = STRONG_AUTHENTICATORS
        self.assert_value(payload, True)
        payload["authenticators"] = STRONG_AUTHENTICATORS + [{"key": "phone_number", "status": "ACTIVE"}]
        self.assert_value(payload, False)

    def test_only_knowledge_methods_listed_leaves_possession_open(self):
        payload = copy.deepcopy(REAL_PASS)
        knowledge_only = rule("Default")
        knowledge_only["actions"]["appSignOn"]["verificationMethod"]["constraints"] = [
            {"knowledge": {"required": True, "authenticationMethods": [{"key": "okta_password", "method": "password"}]},
             "possession": {}}]
        payload["result"]["accessRules"][1] = [knowledge_only]
        payload["result"]["authenticators"] = STRONG_AUTHENTICATORS + [{"key": "phone_number", "status": "ACTIVE"}]
        self.assert_value(payload, False)
        payload["result"]["authenticators"] = STRONG_AUTHENTICATORS
        self.assert_value(payload, True)

    def test_one_constraint_without_possession_methods_leaves_the_rule_open(self):
        payload = copy.deepcopy(REAL_PASS)
        payload["result"]["accessRules"] = [[rule("Admin", methods=STRONG_METHODS)], [rule("Default", methods=STRONG_METHODS)],
                                            [rule("Hardware", methods=STRONG_METHODS)], []]
        payload["result"]["accessRules"][1][0]["actions"]["appSignOn"]["verificationMethod"]["constraints"].append(
            {"knowledge": {"required": True, "types": ["password"]}})
        payload["result"]["authenticators"] = STRONG_AUTHENTICATORS + [{"key": "phone_number", "status": "ACTIVE"}]
        self.assert_value(payload, False)

    def test_classic_is_judged_when_the_access_policy_read_fails(self):
        for failed in ({"errorCode": "E0000001", "errorSummary": "Api validation failed: type"}, None, "oops"):
            payload = copy.deepcopy(CLASSIC)
            payload["accessPolicies"] = failed
            self.assert_value(payload, True)
            failing = copy.deepcopy(payload)
            failing["signOnRules"][0][0]["actions"]["signon"]["requireFactor"] = False
            self.assert_value(failing, False)

    # --- not evaluated (never False) --------------------------------------------------------

    def test_factor_catalogue_is_not_evaluated(self):
        self.assert_value(FACTOR_CATALOGUE, None)
        self.assert_value(json.dumps(FACTOR_CATALOGUE), None)

    def test_empty_and_error_bodies_are_not_evaluated(self):
        for payload in ({}, [], "{}", "null", None, "not json", 5,
                        {"errorCode": "E0000006", "errorSummary": "denied"}, {"error": True, "statusCode": 403},
                        {"result": {}}, {"accessPolicies": [], "accessRules": [], "signOnPolicies": [], "signOnRules": []}):
            self.assert_value(payload, None)

    def test_partial_reads_are_not_evaluated(self):
        no_rules = copy.deepcopy(REAL_PASS["result"])
        del no_rules["accessRules"]
        self.assert_value(no_rules, None)
        short = copy.deepcopy(REAL_PASS["result"])
        short["accessRules"] = short["accessRules"][:2]
        self.assert_value(short, None)
        unreadable = copy.deepcopy(REAL_PASS["result"])
        unreadable["accessRules"][1] = {"error": True, "statusCode": 500}
        self.assert_value(unreadable, None)
        no_policies = copy.deepcopy(REAL_PASS["result"])
        no_policies["accessPolicies"] = "oops"
        self.assert_value(no_policies, None)
        empty_policy = copy.deepcopy(REAL_PASS["result"])
        empty_policy["accessRules"][1] = [rule("Off", status="INACTIVE")]
        self.assert_value(empty_policy, None)

    def test_no_allowing_rule_is_not_evaluated(self):
        payload = copy.deepcopy(REAL_PASS["result"])
        payload["accessRules"] = [[rule("Refuse", access="DENY")], [rule("Refuse", access="DENY")],
                                  [rule("Refuse", access="DENY")], []]
        self.assert_value(payload, None)

    def test_unread_verification_method_is_not_evaluated(self):
        for kind in ("AUTH_METHOD_CHAIN", "ID_PROOFING", ""):
            payload = copy.deepcopy(REAL_PASS)
            payload["result"]["accessRules"][1] = [rule("Default", kind=kind)]
            self.assert_value(payload, None)

    def test_rules_without_listed_methods_and_no_authenticator_list_are_not_evaluated(self):
        for authenticators in (None, [], {"errorCode": "E0000006", "errorSummary": "denied"}, "oops"):
            payload = copy.deepcopy(REAL_PASS)
            payload["result"]["authenticators"] = authenticators
            self.assert_value(payload, None)
            out = load().transform(payload)
            self.assertIn("authenticator list", out["additionalInfo"]["dataCollection"]["errors"][0])
            classic = copy.deepcopy(CLASSIC)
            classic["factors"] = authenticators
            self.assert_value(classic, None)

    def test_a_failed_authenticator_read_names_the_error(self):
        payload = copy.deepcopy(REAL_PASS)
        payload["result"]["authenticators"] = {"errorCode": "E0000006", "errorSummary": "You do not have permission"}
        out = load().transform(payload)
        self.assertIsNone(out["transformedResponse"][KEY])
        self.assertIn("authenticator list read failed: You do not have permission",
                      out["additionalInfo"]["dataCollection"]["errors"][0])

    def test_identity_engine_global_session_does_not_stand_in_for_failed_app_policies(self):
        payload = copy.deepcopy(REAL_PASS["result"])
        payload["accessPolicies"] = {"errorCode": "E0000006", "errorSummary": "denied"}
        self.assert_value(payload, None)

    def test_neither_policy_source_readable_is_not_evaluated(self):
        payload = copy.deepcopy(CLASSIC)
        payload["accessPolicies"] = None
        payload["signOnRules"] = "oops"
        self.assert_value(payload, None)

    def test_identity_engine_with_no_active_app_policy_is_not_judged_from_global_session(self):
        payload = copy.deepcopy(REAL_PASS["result"])
        for p in payload["accessPolicies"]:
            p["status"] = "INACTIVE"
        self.assert_value(payload, None)

    def test_malformed_possession_lists_are_not_a_restriction(self):
        for listed in ([None], ["okta_verify"], [{}], [{"key": "okta_verify"}, 5]):
            payload = copy.deepcopy(REAL_PASS)
            weird = rule("Default", methods=STRONG_METHODS)
            weird["actions"]["appSignOn"]["verificationMethod"]["constraints"][0]["possession"]["authenticationMethods"] = listed
            payload["result"]["accessRules"][1] = [weird]
            payload["result"]["authenticators"] = STRONG_AUTHENTICATORS + [{"key": "phone_number", "status": "ACTIVE"}]
            self.assert_value(payload, False)
        payload = copy.deepcopy(REAL_PASS)
        bad = rule("Default", methods=STRONG_METHODS)
        bad["actions"]["appSignOn"]["verificationMethod"]["constraints"].append("not an object")
        payload["result"]["accessRules"][1] = [bad]
        payload["result"]["authenticators"] = STRONG_AUTHENTICATORS + [{"key": "phone_number", "status": "ACTIVE"}]
        self.assert_value(payload, False)

    def test_weak_entry_without_status_counts_as_on(self):
        payload = copy.deepcopy(REAL_PASS)
        payload["result"]["authenticators"] = STRONG_AUTHENTICATORS + [{"key": "phone_number"}]
        self.assert_value(payload, False)
        classic = copy.deepcopy(CLASSIC)
        classic["factors"].append({"factorType": "sms", "provider": "EXAMPLE"})
        self.assert_value(classic, False)

    def test_wrapped_failed_read_names_the_error(self):
        payload = copy.deepcopy(REAL_PASS)
        payload["result"]["authenticators"] = {"apiResponse": {"errorCode": "E0000006", "errorSummary": "denied here"}}
        out = load().transform(payload)
        self.assertIsNone(out["transformedResponse"][KEY])
        self.assertIn("read failed: denied here", out["additionalInfo"]["dataCollection"]["errors"][0])

    def test_classic_without_active_policy_is_not_evaluated(self):
        payload = copy.deepcopy(CLASSIC)
        payload["signOnPolicies"][0]["status"] = "INACTIVE"
        self.assert_value(payload, None)


if __name__ == "__main__":
    unittest.main()
