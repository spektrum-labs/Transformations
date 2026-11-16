"""isSessionTimeoutConfigured reads Okta global session (OKTA_SIGN_ON) and app authentication (ACCESS_POLICY)
policies and rules from getMfaPolicyRules.

Fixture shape mirrors a real getMfaPolicyRules read (ids and names replaced): two active global session policies,
values stringified the way Integration-Service returns them. The custom (passwordless) policy carries no Default Rule:
Okta documents that only the Default Policy has one. The Default Policy's Default Rule sets maxSessionLifetimeMinutes
"0", which Okta documents as "no maximum lifetime". Identity Engine (rules carry primaryFactor): app authentication
policies end in a system Catch-all Rule and set reauthenticateIn; the longest app interval is 12 hours.
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


def app_policy(pid, name, system="False", kind="APP", status="ACTIVE"):
    return {"id": pid, "name": name, "status": status, "system": system, "type": "ACCESS_POLICY",
            "_embedded": {"resourceType": kind}}


def app_rule(name, reauth, access="ALLOW", status="ACTIVE", system="False", method_type="ASSURANCE"):
    method = {"type": method_type, "factorMode": "2FA", "reauthenticateIn": reauth}
    if reauth is None:
        del method["reauthenticateIn"]
    return {"id": "rul-" + name.lower().replace(" ", "-"), "name": name, "status": status, "system": system,
            "type": "ACCESS_POLICY", "actions": {"appSignOn": {"access": access, "verificationMethod": method}}}


REAL = {"result": {
    "signOnPolicies": [
        {"id": "pol-1", "name": "Passwordless Policy", "status": "ACTIVE", "system": "False", "priority": "1"},
        {"id": "pol-2", "name": "Default Policy", "status": "ACTIVE", "system": "True", "priority": "2"},
    ],
    "signOnRules": [
        [rule("Passwordless", "240"), rule("Contractors", "480", priority="2")],
        [rule("Default Rule", "0", system="True")],
    ],
    "accessPolicies": [
        app_policy("rst-1", "Admin Console"),
        app_policy("rst-2", "Dashboard"),
        app_policy("rst-3", "Default Policy", system="True"),
        app_policy("rst-4", "Account Management", kind="END_USER_ACCOUNT_MANAGEMENT"),
    ],
    "accessRules": [
        [app_rule("Admins", "PT0S"), app_rule("Catch-all Rule", "PT12H", system="True")],
        [app_rule("Catch-all Rule", "PT2H", system="True")],
        [app_rule("Catch-all Rule", "PT12H", system="True"), ],
        [app_rule("Catch-all Rule", "PT43800H", system="True")],
    ],
}}


def classic(data):
    """The same global session rules as a Classic Engine org: no primaryFactor and no authentication policies."""
    data = copy.deepcopy(data)
    for rules in data["result"]["signOnRules"]:
        for r in rules:
            r["actions"]["signon"].pop("primaryFactor", None)
    data["result"]["accessPolicies"] = []
    data["result"]["accessRules"] = []
    return data


NO_LIMIT = 43800 * 60
CLASSIC = classic(REAL)


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

    def set_lifetime(self, data, policy, index, value):
        data["result"]["signOnRules"][policy][index]["actions"]["signon"]["session"]["maxSessionLifetimeMinutes"] = value

    # Identity Engine: the app authentication policies bound what the global session leaves unlimited.

    def test_real_shape_unlimited_global_session_is_bounded_by_app_reauthentication(self):
        full = self.full(REAL)
        out = full["transformedResponse"]
        self.assertEqual(full["additionalInfo"]["dataCollection"]["status"], "success")
        self.assertEqual(out[KEY], 720)
        self.assertTrue(out["sessionLifetimeUnlimited"])
        self.assertIsNone(out["maxSessionLifetimeMinutes"])
        self.assertEqual(out["appReauthenticateMinutes"], 720)
        self.assertEqual(out["maxSessionIdleMinutes"], 120)
        self.assertEqual(out["appPoliciesJudged"], 3)  # the account management policy is not app sign-in
        self.assertEqual(out["appAllowRuleCount"], 4)
        self.assertTrue(ts_less_than(out[KEY], "1440"))
        self.assertFalse(ts_less_than(out[KEY], "480"))
        self.assertIn("app re-authentication interval is 720 minutes",
                      full["additionalInfo"]["evaluation"]["passReasons"][0])

    def test_flipped_once_per_session_app_rule_with_unlimited_global_session_fails_every_threshold(self):
        data = copy.deepcopy(REAL)
        data["result"]["accessRules"][1][0]["actions"]["appSignOn"]["verificationMethod"]["reauthenticateIn"] = "PT43800H"
        full = self.full(data)
        out = full["transformedResponse"]
        self.assertEqual(out[KEY], NO_LIMIT)
        self.assertEqual(full["additionalInfo"]["dataCollection"]["status"], "success")
        for threshold in ["480", "1440", "10080", "129600"]:
            self.assertFalse(ts_less_than(out[KEY], threshold), threshold)
        self.assertIn("once per session", " ".join(full["additionalInfo"]["evaluation"]["failReasons"]))
        self.assertTrue(full["additionalInfo"]["evaluation"]["recommendations"])

    def test_bounded_global_session_shorter_than_app_interval_decides(self):
        data = copy.deepcopy(REAL)
        self.set_lifetime(data, 1, 0, "240")
        out = self.out(data)
        self.assertEqual(out[KEY], 480)
        self.assertEqual(out["maxSessionLifetimeMinutes"], 480)
        self.assertFalse(out["sessionLifetimeUnlimited"])

    def test_app_interval_shorter_than_bounded_global_session_decides(self):
        data = copy.deepcopy(REAL)
        self.set_lifetime(data, 1, 0, "20160")
        self.assertEqual(self.out(data)[KEY], 720)

    def test_deny_inactive_and_non_app_policies_do_not_set_the_app_interval(self):
        data = copy.deepcopy(REAL)
        data["result"]["accessRules"][0].insert(0, app_rule("Blocked", "PT43800H", access="DENY"))
        data["result"]["accessRules"][1].insert(0, app_rule("Old", "PT43800H", status="INACTIVE"))
        data["result"]["accessPolicies"].append(app_policy("rst-5", "Retired", status="INACTIVE"))
        data["result"]["accessRules"].append([app_rule("Catch-all Rule", "PT43800H", system="True")])
        self.assertEqual(self.out(data)[KEY], 720)

    def constrain(self, data, policy, index, rule_level, **factors):
        """Give an ASSURANCE rule constraints; each factor kwarg is its own reauthenticateIn (None = inherit)."""
        method = data["result"]["accessRules"][policy][index]["actions"]["appSignOn"]["verificationMethod"]
        method["reauthenticateIn"] = rule_level
        constraint = {}
        for kind, own in factors.items():
            constraint[kind] = {} if own is None else {"reauthenticateIn": own}
        method["constraints"] = [constraint]

    def test_constraint_interval_overrides_the_rule_level_value_upward(self):
        data = copy.deepcopy(REAL)
        self.constrain(data, 1, 0, "PT2H", knowledge="PT24H", possession="PT24H")
        out = self.out(data)
        self.assertEqual(out[KEY], 1440)  # rule-level PT2H would have reported 720 from the other rules
        self.assertEqual(out["appReauthenticateMinutes"], 1440)

    def test_constraint_interval_overrides_the_rule_level_value_downward(self):
        data = copy.deepcopy(REAL)
        self.constrain(data, 0, 1, "PT12H", possession="PT1H")
        self.constrain(data, 2, 0, "PT12H", knowledge="PT1H", possession=None)
        self.assertEqual(self.out(data)[KEY], 120)

    def method_of(self, data):
        """The one verificationMethod shared by every app ALLOW rule, so the constraints alone set the bound."""
        shared = copy.deepcopy(self.method_template(data))
        for rules in data["result"]["accessRules"]:
            for rule in rules:
                rule["actions"]["appSignOn"]["verificationMethod"] = shared
        return shared

    def method_template(self, data):
        return data["result"]["accessRules"][1][0]["actions"]["appSignOn"]["verificationMethod"]

    def test_2fa_constraint_takes_the_shortest_kind_and_the_longest_constraint(self):
        data = copy.deepcopy(REAL)
        method = self.method_of(data)
        method["factorMode"] = "2FA"
        method["reauthenticateIn"] = "PT2H"
        method["constraints"] = [{"knowledge": {"reauthenticateIn": "PT10H"}, "possession": {}},
                                 {"possession": {"reauthenticateIn": "PT5H"},
                                  "knowledge": {"reauthenticateIn": "PT1H"}}]
        self.assertEqual(self.out(data)[KEY], 120)  # min(10h, inherited 2h)=2h; min(5h, 1h)=1h; longest 2h

    def test_1fa_constraint_takes_the_longest_kind(self):
        data = copy.deepcopy(REAL)
        method = self.method_of(data)
        method["factorMode"] = "1FA"
        method["reauthenticateIn"] = "PT2H"
        method["constraints"] = [{"knowledge": {"reauthenticateIn": "PT10H"}, "possession": {"reauthenticateIn": "PT1H"}}]
        self.assertEqual(self.out(data)[KEY], 600)

    def test_required_false_does_not_drop_a_kind_or_a_constraint(self):
        # mixed alternatives: the second constraint has no own interval, so it re-authenticates at the rule level
        data = copy.deepcopy(REAL)
        method = self.method_of(data)
        method["reauthenticateIn"] = "PT12H"
        method["constraints"] = [{"possession": {"reauthenticateIn": "PT1H"}},
                                 {"possession": {"required": False,
                                                 "excludedAuthenticationMethods": [{"key": "phone_number"}]}}]
        self.assertEqual(self.out(data)[KEY], 720)
        method["constraints"][1] = {}
        self.assertEqual(self.out(data)[KEY], 720)

    def test_2fa_rule_excluding_phone_still_counts_the_possession_interval(self):
        data = copy.deepcopy(REAL)
        method = self.method_of(data)
        method["factorMode"] = "2FA"
        method["reauthenticateIn"] = "PT12H"
        method["constraints"] = [{"knowledge": {"required": True},
                                  "possession": {"required": False, "reauthenticateIn": "PT1H",
                                                 "excludedAuthenticationMethods": [{"key": "phone_number"}]}}]
        self.assertEqual(self.out(data)[KEY], 60)

    def test_1fa_required_false_kind_does_not_bound_a_path_that_skips_it(self):
        # (a) a password-only user never touches possession, so the rule-level interval is the worst case
        data = copy.deepcopy(REAL)
        method = self.method_of(data)
        method["factorMode"] = "1FA"
        method["reauthenticateIn"] = "PT12H"
        method["constraints"] = [{"possession": {"required": "False", "reauthenticateIn": "PT1H",
                                                 "excludedAuthenticationMethods": [{"key": "phone_number"}]}}]
        out = self.out(data)
        self.assertEqual(out[KEY], 720)
        self.assertFalse(ts_less_than(out[KEY], "480"))

    def test_2fa_required_false_knowledge_is_not_bound_when_possession_alone_can_meet_2fa(self):
        # (b) possession with user verification, never the password: the 43,800 h rule-level value applies
        for possession in ({"userVerification": "REQUIRED"}, None):  # (c) no possession key at all
            data = copy.deepcopy(REAL)
            method = self.method_of(data)
            method["factorMode"] = "2FA"
            method["reauthenticateIn"] = "PT43800H"
            constraint = {"knowledge": {"required": "False", "reauthenticateIn": "PT1H",
                                        "excludedAuthenticationMethods": [{"key": "security_question"}]}}
            if possession is not None:
                constraint["possession"] = possession
            method["constraints"] = [constraint]
            out = self.out(data)
            self.assertEqual(out[KEY], NO_LIMIT)
            self.assertFalse(ts_less_than(out[KEY], "10080"))

    def test_2fa_required_knowledge_is_bound_with_possession(self):
        data = copy.deepcopy(REAL)
        method = self.method_of(data)
        method["factorMode"] = "2FA"
        method["reauthenticateIn"] = "PT12H"
        method["constraints"] = [{"knowledge": {"required": True, "reauthenticateIn": "PT1H"}, "possession": {}}]
        self.assertEqual(self.out(data)[KEY], 60)

    def test_non_object_constraint_or_factor_is_unevaluated(self):
        for bad in (["PT1H"], [None], [{"possession": "PT1H"}], [{"possession": []}]):
            data = copy.deepcopy(REAL)
            method = self.method_of(data)
            method["reauthenticateIn"] = "PT2H"
            method["constraints"] = bad
            self.assert_unevaluated(data)

    def test_empty_constraint_inherits_the_rule_level_value(self):
        data = copy.deepcopy(REAL)
        method = self.method_of(data)
        method["reauthenticateIn"] = "PT3H"
        method["constraints"] = [{}]
        self.assertEqual(self.out(data)[KEY], 180)
        del method["reauthenticateIn"]
        self.assert_unevaluated(data)

    def test_constraint_with_unreadable_interval_is_unevaluated(self):
        data = copy.deepcopy(REAL)
        self.constrain(data, 1, 0, "PT2H", knowledge="soon")
        self.assert_unevaluated(data)

    def test_auth_method_chain_interval_is_read(self):
        data = copy.deepcopy(REAL)
        method = {"type": "AUTH_METHOD_CHAIN", "reauthenticateIn": "P1D",
                  "chains": [{"authenticationMethods": [{"key": "okta_password", "method": "password"}],
                              "reauthenticateIn": "P1D"}]}
        data["result"]["accessRules"][1][0]["actions"]["appSignOn"]["verificationMethod"] = method
        self.assertEqual(self.out(data)[KEY], 1440)
        del method["reauthenticateIn"]
        method["chains"].append({"authenticationMethods": [], "reauthenticateIn": "P2D"})
        self.assertEqual(self.out(data)[KEY], 2880)
        method["chains"][1]["reauthenticateIn"] = "soon"
        self.assert_unevaluated(data)

    def test_unreadable_app_interval_is_unevaluated(self):
        for bad in [None, "", "12 hours", "P", "PT", "P1DT", 720]:
            data = copy.deepcopy(REAL)
            data["result"]["accessRules"][0][0] = app_rule("Admins", bad)
            self.assert_unevaluated(data)

    def test_identity_engine_without_readable_app_policies_is_unevaluated(self):
        for access, rules in [([], []), (None, None), ([app_policy("rst-3", "Default Policy", system="True")], [])]:
            data = copy.deepcopy(REAL)
            data["result"]["accessPolicies"] = access
            data["result"]["accessRules"] = rules
            self.assert_unevaluated(data)
        data = copy.deepcopy(REAL)
        data["result"]["accessRules"][2] = {"errorCode": "E0000006"}
        self.assert_unevaluated(data)

    def test_cut_app_policy_or_rule_lists_are_unevaluated(self):
        data = copy.deepcopy(REAL)
        data["result"]["accessPolicies"][2]["system"] = "False"
        self.assert_unevaluated(data)  # no system default authentication policy
        data = copy.deepcopy(REAL)
        data["result"]["accessRules"][1] = [app_rule("Office", "PT1H")]
        self.assert_unevaluated(data)  # no Catch-all Rule
        data = copy.deepcopy(REAL)
        data["result"]["accessRules"][0] = ([app_rule("Rule " + str(i), "PT1H") for i in range(19)]
                                            + [app_rule("Catch-all Rule", "PT1H", system="True")])
        self.assert_unevaluated(data)  # exactly one page of rules
        data = copy.deepcopy(REAL)
        data["result"]["accessPolicies"] = [app_policy("rst-" + str(i), "P" + str(i)) for i in range(19)]
        data["result"]["accessPolicies"].append(app_policy("rst-x", "Default Policy", system="True"))
        data["result"]["accessRules"] = [[app_rule("Catch-all Rule", "PT1H", system="True")] for i in range(20)]
        self.assert_unevaluated(data)  # exactly one page of policies

    def test_synthetic_fixture_unlimited_default_rule_and_once_per_session_apps_fails(self):
        body = json.loads((FIXTURES / "okta_signon_passwordless_no_default_rule_unlimited_synthetic.json").read_text())
        full = self.full(body)
        out = full["transformedResponse"]
        self.assertEqual(full["additionalInfo"]["dataCollection"]["status"], "success")
        self.assertEqual(out[KEY], NO_LIMIT)
        self.assertFalse(ts_less_than(out[KEY], "10080"))
        self.assertTrue(full["additionalInfo"]["evaluation"]["failReasons"])

    def test_synthetic_fixture_limited_default_rule_passes(self):
        body = json.loads((FIXTURES / "okta_signon_passwordless_no_default_rule_limited_synthetic.json").read_text())
        full = self.full(body)
        out = full["transformedResponse"]
        self.assertEqual(out[KEY], 720)
        self.assertTrue(ts_less_than(out[KEY], "10080"))
        self.assertFalse(ts_less_than(out[KEY], "480"))
        self.assertTrue(full["additionalInfo"]["evaluation"]["passReasons"][0].startswith("Okta sessions"))

    # Classic Engine: the global session lifetime alone.

    def test_classic_no_lifetime_limit_fails_every_threshold(self):
        full = self.full(CLASSIC)
        out = full["transformedResponse"]
        self.assertEqual(out[KEY], NO_LIMIT)
        self.assertEqual(full["additionalInfo"]["dataCollection"]["status"], "success")
        self.assertTrue(out["sessionLifetimeUnlimited"])
        self.assertFalse(ts_less_than(out[KEY], "10080"))
        self.assertFalse(ts_less_than(out[KEY], "480"))
        reasons = full["additionalInfo"]["evaluation"]["failReasons"]
        self.assertTrue(all(r.startswith("Okta ") for r in reasons), reasons)
        self.assertIn("Okta policy: 'Default Policy' rule 'Default Rule' sets no time limit", " ".join(reasons))

    def test_classic_every_rule_limited_reports_the_longest(self):
        data = copy.deepcopy(CLASSIC)
        self.set_lifetime(data, 1, 0, "720")
        out = self.out(data)
        self.assertEqual(out[KEY], 720)
        self.assertEqual(out["allowRuleCount"], 3)
        self.assertIsNone(out["appReauthenticateMinutes"])
        self.assertTrue(ts_less_than(out[KEY], "10080"))
        self.assertFalse(ts_less_than(out[KEY], "480"))

    def test_classic_longer_than_seven_days_fails_threshold(self):
        data = copy.deepcopy(CLASSIC)
        self.set_lifetime(data, 1, 0, "20160")
        out = self.out(data)
        self.assertEqual(out[KEY], 20160)
        self.assertFalse(ts_less_than(out[KEY], "10080"))

    def test_classic_unreadable_access_list_is_ignored(self):
        data = copy.deepcopy(CLASSIC)
        self.set_lifetime(data, 1, 0, "600")
        data["result"]["accessPolicies"] = None
        self.assertEqual(self.out(data)[KEY], 600)

    def test_integer_values_are_read_too(self):
        data = copy.deepcopy(CLASSIC)
        self.set_lifetime(data, 0, 0, 480)
        self.set_lifetime(data, 1, 0, 600)
        self.assertEqual(self.out(data)[KEY], 600)

    def test_deny_inactive_rules_and_inactive_policies_are_not_judged(self):
        data = copy.deepcopy(CLASSIC)
        data["result"]["signOnRules"][1] = [rule("Default Rule", "0", access="DENY", system="True")]
        data["result"]["signOnRules"][0].append(rule("Old rule", "0", status="INACTIVE", priority="2"))
        data["result"]["signOnPolicies"].append({"id": "pol-3", "name": "Retired", "status": "INACTIVE"})
        data["result"]["signOnRules"].append([rule("Retired rule", "0")])
        data = classic(data)
        out = self.out(data)
        self.assertEqual(out[KEY], 480)
        self.assertEqual(out["allowRuleCount"], 2)

    def test_policy_list_cut_before_the_default_policy_is_unevaluated_not_a_pass(self):
        # Okta always returns the Default Policy. A list holding only a 120-minute custom policy would pass a
        # 480-minute bar, while the full list (with an unlimited Default Rule) fails it.
        for base in [REAL, CLASSIC]:
            data = copy.deepcopy(base)
            data["result"]["signOnPolicies"] = [data["result"]["signOnPolicies"][0]]
            data["result"]["signOnRules"] = [[rule("Short sessions", "120")]]
            full = self.full(data)
            self.assertIsNone(full["transformedResponse"][KEY])
            self.assertEqual(full["additionalInfo"]["dataCollection"]["status"], "error")
            self.assertIn("system default policy", " ".join(full["additionalInfo"]["dataCollection"]["errors"]))
            self.assertFalse(ts_less_than(full["transformedResponse"][KEY], "480"))

    def test_default_policy_without_its_default_rule_is_unevaluated(self):
        # Only the Default Policy has a Default Rule, always last; without it that rule list was cut short.
        data = copy.deepcopy(CLASSIC)
        data["result"]["signOnRules"][1] = [rule("Office network", "120")]
        data = classic(data)
        full = self.full(data)
        self.assertIsNone(full["transformedResponse"][KEY])
        self.assertEqual(full["additionalInfo"]["dataCollection"]["status"], "error")
        self.assertIn("Default Rule", " ".join(full["additionalInfo"]["dataCollection"]["errors"]))

    def test_custom_policy_without_a_default_rule_is_judged_on_its_rules(self):
        data = copy.deepcopy(CLASSIC)
        data["result"]["signOnRules"][0] = [rule("Passwordless", "240")]
        self.set_lifetime(data, 1, 0, "180")
        data = classic(data)
        full = self.full(data)
        self.assertEqual(full["additionalInfo"]["dataCollection"]["status"], "success")
        self.assertEqual(full["transformedResponse"][KEY], 240)
        self.assertEqual(full["transformedResponse"]["allowRuleCount"], 2)
        self.assertTrue(ts_less_than(full["transformedResponse"][KEY], "10080"))
        self.assertFalse(ts_less_than(full["transformedResponse"][KEY], "120"))

    def test_custom_policy_without_a_default_rule_fails_on_its_own_unlimited_rule(self):
        data = copy.deepcopy(CLASSIC)
        data["result"]["signOnRules"][0] = [rule("Passwordless", "0")]
        self.set_lifetime(data, 1, 0, "180")
        data = classic(data)
        full = self.full(data)
        self.assertEqual(full["transformedResponse"][KEY], NO_LIMIT)
        self.assertFalse(ts_less_than(full["transformedResponse"][KEY], "10080"))
        reasons = full["additionalInfo"]["evaluation"]["failReasons"]
        self.assertIn("Okta policy: 'Passwordless Policy' rule 'Passwordless' sets no time limit", " ".join(reasons))

    def test_active_policy_with_no_rules_is_unevaluated(self):
        data = copy.deepcopy(CLASSIC)
        data["result"]["signOnRules"][0] = []
        self.assert_unevaluated(data)
        data["result"]["signOnPolicies"][0]["status"] = "INACTIVE"
        self.assertEqual(self.out(data)[KEY], NO_LIMIT)

    def test_rule_list_one_page_long_is_unevaluated(self):
        for size in [20, 200]:
            data = copy.deepcopy(CLASSIC)
            self.set_lifetime(data, 1, 0, "60")
            data["result"]["signOnRules"][0] = [rule("Rule " + str(i), "60", priority=str(i)) for i in range(1, size + 1)]
            data = classic(data)
            full = self.full(data)
            self.assertIsNone(full["transformedResponse"][KEY], size)
            self.assertIn("returned exactly " + str(size) + " rules", " ".join(full["additionalInfo"]["dataCollection"]["errors"]))
            for other in [size - 1, size + 1]:
                data["result"]["signOnRules"][0] = [rule("Rule " + str(i), "60", priority=str(i)) for i in range(1, other + 1)]
                data = classic(data)
                self.assertEqual(self.out(data)[KEY], 60, other)

    def test_default_policy_one_page_long_is_unevaluated(self):
        data = copy.deepcopy(CLASSIC)
        data["result"]["signOnRules"][1] = [rule("Rule " + str(i), "60", priority=str(i)) for i in range(1, 20)]
        data["result"]["signOnRules"][1].append(rule("Default Rule", "60", system="True"))
        self.assert_unevaluated(classic(data))

    def test_default_rule_flag_as_boolean_is_read(self):
        for base in [REAL, CLASSIC]:
            data = copy.deepcopy(base)
            for rules in data["result"]["signOnRules"] + data["result"]["accessRules"]:
                for r in rules:
                    r["system"] = r["system"] == "True"
            for p in data["result"]["accessPolicies"]:
                p["system"] = p["system"] == "True"
            self.assertEqual(self.out(data)[KEY], self.out(base)[KEY])

    def test_value_is_always_a_number_or_none(self):
        # A boolean would coerce to 0 minutes in a numeric comparison and pass; a string cannot be compared.
        for body in [REAL, CLASSIC, {}, None]:
            value = self.out(body)[KEY]
            self.assertTrue(value is None or (isinstance(value, int) and not isinstance(value, bool)), value)

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
        data = copy.deepcopy(REAL)
        data["result"]["accessRules"] = data["result"]["accessRules"][:2]
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
            self.set_lifetime(data, 0, 0, bad)
            self.assert_unevaluated(data)

    def test_transformation_error_is_unevaluated(self):
        self.assert_unevaluated(b"\xff not json")


if __name__ == "__main__":
    unittest.main()
