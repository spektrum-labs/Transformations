"""isSessionTimeoutConfigured reads Okta global session (OKTA_SIGN_ON) policies and rules from getMfaPolicyRules.

Fixture shape mirrors a real getMfaPolicyRules read (ids and names replaced): two active global session policies,
values stringified the way Integration-Service returns them. The custom (passwordless) policy carries no Default Rule:
Okta documents that only the Default Policy has one. The Default Policy's Default Rule sets maxSessionLifetimeMinutes
"0", which Okta documents as "no maximum lifetime".
"""
import copy
import json
import importlib.util
import unittest
from pathlib import Path

PATH = Path(__file__).with_name("issessiontimeoutconfigured.py")
FIXTURES = Path(__file__).with_name("fixtures")
KEY = "isSessionTimeoutConfigured"


def load():
    spec = importlib.util.spec_from_file_location("issessiontimeoutconfigured", PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def rule(name, lifetime, idle="120", access="ALLOW", status="ACTIVE", system="False", priority="1"):
    return {"id": "rul-" + name.lower().replace(" ", "-"), "name": name, "status": status, "system": system,
            "priority": priority, "type": "SIGN_ON",
            "conditions": {"people": {"users": {"exclude": []}}, "network": {"connection": "ANYWHERE"}},
            "actions": {"signon": {"access": access, "requireFactor": "False",
                                   "primaryFactor": "PASSWORD_IDP_ANY_FACTOR", "rememberDeviceByDefault": "False",
                                   "session": {"usePersistentCookie": "False", "maxSessionIdleMinutes": idle,
                                               "maxSessionLifetimeMinutes": lifetime}}}}


REAL = {"result": {
    "signOnPolicies": [
        {"id": "pol-1", "name": "Passwordless Policy", "status": "ACTIVE", "system": "False", "priority": "1"},
        {"id": "pol-2", "name": "Default Policy", "status": "ACTIVE", "system": "True", "priority": "2"},
    ],
    "signOnRules": [
        [rule("Passwordless", "240"), rule("Contractors", "480", priority="2")],
        [rule("Default Rule", "0", system="True")],
    ],
    "accessPolicies": [],
    "accessRules": [],
}}


def ts_less_than(value, threshold):
    """Token-Service Conditions.lessThan: int(float(value)) <= int(float(threshold)); any exception is False."""
    try:
        return int(float(value)) <= int(float(threshold))
    except Exception:
        return False


class SessionTimeoutTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = load()

    def full(self, payload):
        return self.t.transform(payload)

    def out(self, payload):
        return self.full(payload)["transformedResponse"]

    def assert_unevaluated(self, payload):
        full = self.full(payload)
        self.assertIsNone(full["transformedResponse"][KEY], payload)
        self.assertEqual(full["additionalInfo"]["dataCollection"]["status"], "error", payload)
        self.assertTrue(full["additionalInfo"]["dataCollection"]["errors"], payload)

    def test_real_shape_no_lifetime_limit_is_unlimited_and_fails_threshold(self):
        full = self.full(REAL)
        out = full["transformedResponse"]
        self.assertEqual(out[KEY], "unlimited")
        self.assertEqual(full["additionalInfo"]["dataCollection"]["status"], "success")
        self.assertFalse(ts_less_than(out[KEY], "10080"))
        self.assertFalse(ts_less_than(out[KEY], "480"))
        self.assertTrue(full["additionalInfo"]["evaluation"]["failReasons"])

    def test_flipped_every_rule_limited_reports_the_longest(self):
        data = copy.deepcopy(REAL)
        data["result"]["signOnRules"][1][0]["actions"]["signon"]["session"]["maxSessionLifetimeMinutes"] = "720"
        out = self.out(data)
        self.assertEqual(out[KEY], 720)
        self.assertEqual(out["allowRuleCount"], 3)
        self.assertTrue(ts_less_than(out[KEY], "10080"))
        self.assertFalse(ts_less_than(out[KEY], "480"))

    def test_longer_than_seven_days_fails_threshold(self):
        data = copy.deepcopy(REAL)
        data["result"]["signOnRules"][1][0]["actions"]["signon"]["session"]["maxSessionLifetimeMinutes"] = "20160"
        out = self.out(data)
        self.assertEqual(out[KEY], 20160)
        self.assertFalse(ts_less_than(out[KEY], "10080"))

    def test_integer_values_are_read_too(self):
        data = copy.deepcopy(REAL)
        data["result"]["signOnRules"][0][0]["actions"]["signon"]["session"]["maxSessionLifetimeMinutes"] = 480
        data["result"]["signOnRules"][1][0]["actions"]["signon"]["session"]["maxSessionLifetimeMinutes"] = 600
        self.assertEqual(self.out(data)[KEY], 600)

    def test_deny_inactive_rules_and_inactive_policies_are_not_judged(self):
        data = copy.deepcopy(REAL)
        data["result"]["signOnRules"][1] = [rule("Default Rule", "0", access="DENY", system="True")]
        data["result"]["signOnRules"][0].append(rule("Old rule", "0", status="INACTIVE", priority="2"))
        data["result"]["signOnPolicies"].append({"id": "pol-3", "name": "Retired", "status": "INACTIVE"})
        data["result"]["signOnRules"].append([rule("Retired rule", "0")])
        out = self.out(data)
        self.assertEqual(out[KEY], 480)
        self.assertEqual(out["allowRuleCount"], 2)

    def test_policy_list_cut_before_the_default_policy_is_unevaluated_not_a_pass(self):
        # Okta always returns the Default Policy. A list holding only a 120-minute custom policy would pass a
        # 480-minute bar, while the full list (with an unlimited Default Rule) fails it.
        data = copy.deepcopy(REAL)
        data["result"]["signOnPolicies"] = [data["result"]["signOnPolicies"][0]]
        data["result"]["signOnRules"] = [[rule("Short sessions", "120")]]
        full = self.full(data)
        self.assertIsNone(full["transformedResponse"][KEY])
        self.assertEqual(full["additionalInfo"]["dataCollection"]["status"], "error")
        self.assertIn("Default Policy", " ".join(full["additionalInfo"]["dataCollection"]["errors"]))
        self.assertFalse(ts_less_than(full["transformedResponse"][KEY], "480"))

    def test_default_policy_without_its_default_rule_is_unevaluated(self):
        # Only the Default Policy has a Default Rule, always last; without it that rule list was cut short.
        data = copy.deepcopy(REAL)
        data["result"]["signOnRules"][1] = [rule("Office network", "120")]
        full = self.full(data)
        self.assertIsNone(full["transformedResponse"][KEY])
        self.assertEqual(full["additionalInfo"]["dataCollection"]["status"], "error")
        self.assertIn("Default Rule", " ".join(full["additionalInfo"]["dataCollection"]["errors"]))

    def test_custom_policy_without_a_default_rule_is_judged_on_its_rules(self):
        data = copy.deepcopy(REAL)
        data["result"]["signOnRules"][0] = [rule("Passwordless", "240")]
        data["result"]["signOnRules"][1][0]["actions"]["signon"]["session"]["maxSessionLifetimeMinutes"] = "180"
        full = self.full(data)
        self.assertEqual(full["additionalInfo"]["dataCollection"]["status"], "success")
        self.assertEqual(full["transformedResponse"][KEY], 240)
        self.assertEqual(full["transformedResponse"]["allowRuleCount"], 2)
        self.assertTrue(ts_less_than(full["transformedResponse"][KEY], "10080"))
        self.assertFalse(ts_less_than(full["transformedResponse"][KEY], "120"))

    def test_custom_policy_without_a_default_rule_fails_on_its_own_unlimited_rule(self):
        data = copy.deepcopy(REAL)
        data["result"]["signOnRules"][0] = [rule("Passwordless", "0")]
        data["result"]["signOnRules"][1][0]["actions"]["signon"]["session"]["maxSessionLifetimeMinutes"] = "180"
        full = self.full(data)
        self.assertEqual(full["transformedResponse"][KEY], "unlimited")
        self.assertFalse(ts_less_than(full["transformedResponse"][KEY], "10080"))
        reasons = full["additionalInfo"]["evaluation"]["failReasons"]
        self.assertIn("Okta session policy: 'Passwordless Policy' allows an unlimited session lifetime", " ".join(reasons))

    def test_unlimited_lifetime_fails_and_names_the_tool_scope(self):
        full = self.full(REAL)
        self.assertEqual(full["transformedResponse"][KEY], "unlimited")
        self.assertFalse(ts_less_than(full["transformedResponse"][KEY], "10080"))
        reasons = full["additionalInfo"]["evaluation"]["failReasons"]
        self.assertTrue(all(r.startswith("Okta ") for r in reasons), reasons)
        self.assertIn("Okta session policy: 'Default Policy' allows an unlimited session lifetime", " ".join(reasons))

    def test_active_policy_with_no_rules_is_unevaluated(self):
        data = copy.deepcopy(REAL)
        data["result"]["signOnRules"][0] = []
        self.assert_unevaluated(data)
        data["result"]["signOnPolicies"][0]["status"] = "INACTIVE"
        self.assertEqual(self.out(data)[KEY], "unlimited")

    def test_rule_list_one_page_long_is_unevaluated(self):
        for size in [20, 200]:
            data = copy.deepcopy(REAL)
            data["result"]["signOnRules"][1][0]["actions"]["signon"]["session"]["maxSessionLifetimeMinutes"] = "60"
            data["result"]["signOnRules"][0] = [rule("Rule " + str(i), "60", priority=str(i)) for i in range(1, size + 1)]
            full = self.full(data)
            self.assertIsNone(full["transformedResponse"][KEY], size)
            self.assertIn("returned exactly " + str(size) + " rules", " ".join(full["additionalInfo"]["dataCollection"]["errors"]))
            for other in [size - 1, size + 1]:
                data["result"]["signOnRules"][0] = [rule("Rule " + str(i), "60", priority=str(i)) for i in range(1, other + 1)]
                self.assertEqual(self.out(data)[KEY], 60, other)

    def test_default_policy_one_page_long_is_unevaluated(self):
        data = copy.deepcopy(REAL)
        data["result"]["signOnRules"][1] = [rule("Rule " + str(i), "60", priority=str(i)) for i in range(1, 20)]
        data["result"]["signOnRules"][1].append(rule("Default Rule", "60", system="True"))
        self.assert_unevaluated(data)

    def test_synthetic_fixture_unlimited_default_rule_fails(self):
        body = json.loads((FIXTURES / "okta_signon_passwordless_no_default_rule_unlimited_synthetic.json").read_text())
        full = self.full(body)
        out = full["transformedResponse"]
        self.assertEqual(full["additionalInfo"]["dataCollection"]["status"], "success")
        self.assertEqual(out[KEY], "unlimited")
        self.assertFalse(ts_less_than(out[KEY], "10080"))
        self.assertTrue(full["additionalInfo"]["evaluation"]["failReasons"])

    def test_synthetic_fixture_limited_default_rule_passes(self):
        body = json.loads((FIXTURES / "okta_signon_passwordless_no_default_rule_limited_synthetic.json").read_text())
        full = self.full(body)
        out = full["transformedResponse"]
        self.assertEqual(out[KEY], 720)
        self.assertTrue(ts_less_than(out[KEY], "10080"))
        self.assertFalse(ts_less_than(out[KEY], "480"))
        self.assertTrue(full["additionalInfo"]["evaluation"]["passReasons"][0].startswith("Okta global session policies"))

    def test_default_rule_flag_as_boolean_is_read(self):
        data = copy.deepcopy(REAL)
        for rules in data["result"]["signOnRules"]:
            for r in rules:
                r["system"] = r["system"] == "True"
        self.assertEqual(self.out(data)[KEY], "unlimited")

    def test_value_is_never_a_boolean(self):
        # A boolean would coerce to 0 minutes in a numeric comparison and pass.
        for body in [REAL, {}, None]:
            value = self.out(body)[KEY]
            self.assertNotIsInstance(value, bool)

    def test_empty_none_and_unrelated_bodies_are_unevaluated(self):
        for body in [{}, None, "{}", [], "null", {"result": {}}, {"value": []}]:
            self.assert_unevaluated(body)

    def test_error_bodies_are_unevaluated(self):
        for body in [{"statusCode": 401, "error": "Unauthorized"},
                     {"statusCode": "403", "message": "Forbidden"},
                     {"errorCode": "E0000006", "errorSummary": "You do not have permission to perform the requested action"}]:
            self.assert_unevaluated(body)

    def test_partial_or_misaligned_reads_are_unevaluated(self):
        data = copy.deepcopy(REAL)
        data["result"]["signOnRules"] = data["result"]["signOnRules"][:1]
        self.assert_unevaluated(data)
        data = copy.deepcopy(REAL)
        data["result"]["signOnRules"][1] = {"errorCode": "E0000007"}
        self.assert_unevaluated(data)

    def test_no_active_policy_or_allow_rule_is_unevaluated(self):
        data = copy.deepcopy(REAL)
        for p in data["result"]["signOnPolicies"]:
            p["status"] = "INACTIVE"
        self.assert_unevaluated(data)
        data = copy.deepcopy(REAL)
        data["result"]["signOnRules"] = [[], [rule("Default Rule", "0", access="DENY")]]
        self.assert_unevaluated(data)
        self.assert_unevaluated({"signOnPolicies": [], "signOnRules": []})

    def test_unreadable_session_settings_are_unevaluated(self):
        data = copy.deepcopy(REAL)
        del data["result"]["signOnRules"][0][0]["actions"]["signon"]["session"]
        self.assert_unevaluated(data)
        for bad in ["", "abc", "-5", None, True, 12.5, "7d"]:
            data = copy.deepcopy(REAL)
            data["result"]["signOnRules"][0][0]["actions"]["signon"]["session"]["maxSessionLifetimeMinutes"] = bad
            self.assert_unevaluated(data)

    def test_transformation_error_is_unevaluated(self):
        self.assert_unevaluated(b"\xff not json")


if __name__ == "__main__":
    unittest.main()
