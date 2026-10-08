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
        method["constraints"].append({"possession": {"required": True, "authenticationMethods": methods}})
    return {"id": "rul-" + name, "name": name, "status": status,
            "actions": {"appSignOn": {"access": access, "verificationMethod": method}}}


def app_policy(name, status="ACTIVE"):
    return {"id": "pol-" + name, "name": name, "type": "ACCESS_POLICY", "status": status, "_embedded": {"resourceType": "APP"}}


ACCOUNT_POLICY = {"id": "pol-acct", "name": "Account Management", "type": "ACCESS_POLICY", "status": "ACTIVE",
                  "_embedded": {"resourceType": "END_USER_ACCOUNT_MANAGEMENT"}}
STRONG_METHODS = [{"key": "okta_verify", "method": "push"}, {"key": "webauthn", "method": "webauthn"}]

REAL_PASS = {"result": {
    "signOnPolicies": [{"id": "pol-so", "name": "Global Session", "type": "OKTA_SIGN_ON", "status": "ACTIVE"}],
    "signOnRules": [[{"name": "Default", "status": "ACTIVE", "actions": {"signon": {"access": "ALLOW", "requireFactor": False}}}]],
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
           "accessPolicies": [], "accessRules": []}


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

    def test_classic_without_active_policy_is_not_evaluated(self):
        payload = copy.deepcopy(CLASSIC)
        payload["signOnPolicies"][0]["status"] = "INACTIVE"
        self.assert_value(payload, None)


if __name__ == "__main__":
    unittest.main()
