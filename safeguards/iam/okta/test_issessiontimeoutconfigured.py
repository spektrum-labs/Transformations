"""isSessionTimeoutConfigured reads Okta global session (OKTA_SIGN_ON) policies and rules from getMfaPolicyRules.

Fixture shape mirrors a real getMfaPolicyRules read (tenant A, ids and names replaced): two active global session
policies, values stringified the way Integration-Service returns them. The default policy's default rule sets
maxSessionLifetimeMinutes "0", which Okta documents as "no maximum lifetime".
"""
import copy
import importlib.util
import unittest
from pathlib import Path

PATH = Path(__file__).with_name("issessiontimeoutconfigured.py")
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
        [rule("Passwordless", "240"), rule("Default Rule", "480", system="True", priority="99")],
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

    def test_rule_list_cut_before_its_default_rule_is_unevaluated_not_a_pass(self):
        # Okta lists the Default Rule last. A first page holding only a 120-minute rule would pass a 480-minute bar,
        # while the full list (with an unlimited Default Rule) fails it.
        data = copy.deepcopy(REAL)
        data["result"]["signOnPolicies"] = [data["result"]["signOnPolicies"][0]]
        data["result"]["signOnRules"] = [[rule("Short sessions", "120")]]
        full = self.t.transform(copy.deepcopy(data))
        self.assertIsNone(full["transformedResponse"][KEY])
        self.assertEqual(full["additionalInfo"]["dataCollection"]["status"], "error")
        self.assertIn("Default Rule", " ".join(full["additionalInfo"]["dataCollection"]["errors"]))
        self.assertFalse(ts_less_than(full["transformedResponse"][KEY], "480"))

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
