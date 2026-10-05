"""Five Okta criteria that were mapped to the Okta integration but that nothing evaluated:
passwordOnlyAuthPolicyRulesCount, isRiskBasedAuthenticationEnabled, lockedOutUsersCount,
suspendedUsersCount and isOktaFastPassEnabled.

Every test runs twice: once against the plain module, and once against the same file compiled by the
RestrictedPython replica in tools/, which is how Token-Service runs it.
The fixtures are synthetic. They copy the field shapes Okta's Management API returns, and every id,
login and domain in them is invented.

The rule every test checks: when the data cannot answer, the transform returns None and sets
dataCollection.status to "error". That is the only result Token-Service grades as Unevaluated; a None
with dataCollection "success" grades as Failed.
"""
import copy
import importlib.util
import json
import unittest
from pathlib import Path

HERE = Path(__file__).parent
ROOT = HERE.parents[2]
FIX = HERE / "fixtures"


def plain(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def sandboxed(name):
    spec = importlib.util.spec_from_file_location("restricted_sandbox_" + name, ROOT / "tools" / "restricted_sandbox.py")
    sandbox = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sandbox)
    return sandbox.load((HERE / (name + ".py")).read_text(), "<transformation>")["transform"]


def fixture(name):
    return json.loads((FIX / name).read_text())


# ---------- policy shapes (getMfaPolicyRules) ----------

def ie_rule(name, access="ALLOW", mode="2FA", constraints=None, conditions=None, system=False, priority=0, status="ACTIVE"):
    method = {"type": "ASSURANCE", "factorMode": mode, "reauthenticateIn": "PT2H"}
    if constraints is not None:
        method["constraints"] = constraints
    return {"id": "rul" + name.replace(" ", ""), "name": name, "status": status, "system": system, "priority": priority,
            "type": "ACCESS_POLICY", "conditions": conditions,
            "actions": {"appSignOn": {"access": access, "verificationMethod": method}}}


def session_rule(name, access="ALLOW", require=False, conditions=None, system=False, priority=0):
    return {"id": "rul" + name.replace(" ", ""), "name": name, "status": "ACTIVE", "system": system, "priority": priority,
            "type": "SIGN_ON", "conditions": conditions or {"network": {"connection": "ANYWHERE"}},
            "actions": {"signon": {"access": access, "requireFactor": require, "primaryFactor": "PASSWORD_IDP_ANY_FACTOR",
                                   "session": {"usePersistentCookie": False, "maxSessionIdleMinutes": 120,
                                               "maxSessionLifetimeMinutes": 0}}}}


PASSWORD = [{"knowledge": {"types": ["password"], "reauthenticateIn": "PT2H"}}]
POSSESSION_ONLY = [{"possession": {"deviceBound": "REQUIRED", "phishingResistant": "REQUIRED", "userPresence": "REQUIRED"}}]
HIGH_RISK = {"network": {"connection": "ANYWHERE"}, "riskScore": {"level": "HIGH"}}
ANY_RISK = {"network": {"connection": "ANYWHERE"}, "riskScore": {"level": "ANY"}}


def app_policy(pid, name, kind="APP"):
    return {"id": pid, "name": name, "status": "ACTIVE", "type": "ACCESS_POLICY", "system": False,
            "_embedded": {"resourceType": kind}}


IE = {"result": {
    "signOnPolicies": [{"id": "00pS1", "name": "Default Policy", "status": "ACTIVE", "system": True, "type": "OKTA_SIGN_ON"}],
    "signOnRules": [[session_rule("Default Rule", system=True, priority=1)]],
    "accessPolicies": [app_policy("00pA1", "Okta Dashboard"), app_policy("00pA2", "Any two factors"),
                       app_policy("00pA3", "Okta Account Management Policy", "END_USER_ACCOUNT_MANAGEMENT"),
                       app_policy("00pA4", "Passwordless")],
    "accessRules": [
        [ie_rule("Catch-all Rule", system=True, priority=99)],
        [ie_rule("Catch-all Rule", system=True, priority=99)],
        [ie_rule("Password reset", mode="1FA", constraints=PASSWORD), ie_rule("Catch-all Rule", system=True, priority=99)],
        [ie_rule("FastPass only", mode="1FA", constraints=POSSESSION_ONLY, priority=1),
         ie_rule("Catch-all Rule", access="DENY", system=True, priority=99)],
    ],
}}


class Both:
    NAME = None

    @classmethod
    def setUpClass(cls):
        cls.runs = [plain(cls.NAME), sandboxed(cls.NAME)]

    def each(self, payload):
        return [run(copy.deepcopy(payload)) for run in self.runs]

    def value(self, payload, key):
        values = [out["transformedResponse"][key] for out in self.each(payload)]
        self.assertEqual(values[0], values[1], "plain and sandbox disagree")
        return values[0]

    def assert_unevaluated(self, payload, key):
        for out in self.each(payload):
            self.assertIsNone(out["transformedResponse"][key])
            self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "error")
            self.assertTrue(out["additionalInfo"]["dataCollection"]["errors"])

    def assert_measured(self, payload):
        for out in self.each(payload):
            self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")


class PasswordOnlyRules(Both, unittest.TestCase):
    NAME = "passwordOnlyAuthPolicyRulesCount"
    KEY = NAME

    def test_identity_engine_passwordless_and_two_factor_rules_count_zero(self):
        self.assertEqual(self.value(IE, self.KEY), 0)
        self.assert_measured(IE)

    def test_one_factor_rule_with_no_constraint_counts(self):
        data = copy.deepcopy(IE)
        data["result"]["accessRules"][0] = [ie_rule("Catch-all Rule", mode="1FA", system=True, priority=99)]
        self.assertEqual(self.value(data, self.KEY), 1)
        out = self.runs[0](data)
        self.assertIn("Okta Dashboard / Catch-all Rule", " ".join(out["additionalInfo"]["evaluation"]["failReasons"]))

    def test_one_factor_password_constraint_counts_but_account_management_policy_is_not_judged(self):
        data = copy.deepcopy(IE)
        data["result"]["accessRules"][1] = [ie_rule("Office", mode="1FA", constraints=PASSWORD, priority=1),
                                            ie_rule("Catch-all Rule", system=True, priority=99)]
        self.assertEqual(self.value(data, self.KEY), 1)  # the 1FA rule in END_USER_ACCOUNT_MANAGEMENT is ignored

    def test_inactive_rule_and_deny_rule_do_not_count(self):
        data = copy.deepcopy(IE)
        data["result"]["accessRules"][0] = [ie_rule("Old", mode="1FA", status="INACTIVE", priority=1),
                                            ie_rule("Block", access="DENY", mode="1FA", priority=2),
                                            ie_rule("Catch-all Rule", system=True, priority=99)]
        self.assertEqual(self.value(data, self.KEY), 0)

    def test_classic_engine_judges_global_session_rules(self):
        data = copy.deepcopy(IE)
        data["result"]["accessPolicies"] = []
        data["result"]["accessRules"] = []
        self.assertEqual(self.value(data, self.KEY), 1)  # Default Rule: ALLOW, requireFactor false
        data["result"]["signOnRules"][0][0]["actions"]["signon"]["requireFactor"] = True
        self.assertEqual(self.value(data, self.KEY), 0)

    def test_unknown_verification_method_is_unevaluated(self):
        data = copy.deepcopy(IE)
        data["result"]["accessRules"][0][0]["actions"]["appSignOn"]["verificationMethod"] = {"type": "AUTH_METHOD_CHAIN", "chains": []}
        self.assert_unevaluated(data, self.KEY)

    def test_missing_or_misaligned_rules_are_unevaluated(self):
        data = copy.deepcopy(IE)
        data["result"]["accessRules"] = data["result"]["accessRules"][:2]
        self.assert_unevaluated(data, self.KEY)
        data = copy.deepcopy(IE)
        data["result"]["accessRules"][3] = {"apiResponse": {"errorCode": "E0000006", "errorSummary": "You do not have permission"}}
        self.assert_unevaluated(data, self.KEY)

    def test_full_page_of_rules_is_unevaluated(self):
        data = copy.deepcopy(IE)
        data["result"]["accessRules"][0] = [ie_rule("R" + str(i), priority=i) for i in range(200)]
        self.assert_unevaluated(data, self.KEY)

    def test_truncated_read_is_unevaluated(self):
        data = copy.deepcopy(IE)
        data["paginationTruncated"] = True
        self.assert_unevaluated(data, self.KEY)

    def test_no_evidence_bodies_are_unevaluated(self):
        for body in [{}, None, "{}", [], {"errorCode": "E0000011", "errorSummary": "Invalid token provided"},
                     {"statusCode": 401}, {"result": {"signOnPolicies": []}}]:
            self.assert_unevaluated(body, self.KEY)


class RiskBased(Both, unittest.TestCase):
    NAME = "isRiskBasedAuthenticationEnabled"
    KEY = NAME

    def test_no_risk_condition_is_false(self):
        self.assertIs(self.value(IE, self.KEY), False)
        self.assert_measured(IE)

    def test_high_risk_deny_in_app_policy_is_true(self):
        data = copy.deepcopy(IE)
        data["result"]["accessRules"][0] = [ie_rule("Block high risk", access="DENY", conditions=HIGH_RISK, priority=1),
                                            ie_rule("Catch-all Rule", system=True, priority=99)]
        self.assertIs(self.value(data, self.KEY), True)

    def test_risk_rule_with_same_outcome_as_catch_all_is_false(self):
        data = copy.deepcopy(IE)
        data["result"]["accessRules"][0] = [ie_rule("High risk 2FA", conditions=HIGH_RISK, priority=1),
                                            ie_rule("Catch-all Rule", system=True, priority=99)]
        self.assertIs(self.value(data, self.KEY), False)

    def test_risk_level_any_is_not_a_risk_condition(self):
        data = copy.deepcopy(IE)
        data["result"]["accessRules"][0] = [ie_rule("Any risk deny", access="DENY", conditions=ANY_RISK, priority=1),
                                            ie_rule("Catch-all Rule", system=True, priority=99)]
        self.assertIs(self.value(data, self.KEY), False)

    def test_global_session_risk_behaviors_count(self):
        data = copy.deepcopy(IE)
        data["result"]["signOnRules"][0] = [
            session_rule("New country", require=True, priority=1,
                         conditions={"network": {"connection": "ANYWHERE"}, "risk": {"behaviors": ["New Country"]}}),
            session_rule("Default Rule", system=True, priority=2)]
        self.assertIs(self.value(data, self.KEY), True)

    def test_unreadable_lists_are_unevaluated(self):
        data = copy.deepcopy(IE)
        del data["result"]["signOnRules"]
        self.assert_unevaluated(data, self.KEY)
        data = copy.deepcopy(IE)
        data["result"]["accessRules"][1] = {"apiResponse": {"errorCode": "E0000006"}}
        self.assert_unevaluated(data, self.KEY)

    def test_no_evidence_bodies_are_unevaluated(self):
        for body in [{}, None, "{}", [], {"errorCode": "E0000011"}, {"status_code": 403}]:
            self.assert_unevaluated(body, self.KEY)


class UserCounts(unittest.TestCase):
    CASES = [("lockedOutUsersCount", 2, "locked1@example.com"), ("suspendedUsersCount", 1, "suspended1@example.com")]

    @classmethod
    def setUpClass(cls):
        cls.runs = {name: [plain(name), sandboxed(name)] for name, _, _ in cls.CASES}

    def outs(self, name, payload):
        return [run(copy.deepcopy(payload)) for run in self.runs[name]]

    def test_counts_from_the_user_list_and_names_accounts(self):
        users = fixture("okta_users_list_synthetic.json")
        for name, expected, login in self.CASES:
            for out in self.outs(name, users):
                self.assertEqual(out["transformedResponse"][name], expected)
                self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")
                self.assertIn(login, " ".join(out["additionalInfo"]["evaluation"]["failReasons"]))

    def test_wrapped_bodies_are_read(self):
        users = fixture("okta_users_list_synthetic.json")
        for wrapped in [{"apiResponse": users}, {"status": "success", "data": users}, json.dumps(users)]:
            for name, expected, _ in self.CASES:
                for out in self.outs(name, wrapped):
                    self.assertEqual(out["transformedResponse"][name], expected)

    def test_zero_is_a_pass(self):
        users = [u for u in fixture("okta_users_list_synthetic.json") if u["status"] == "ACTIVE"]
        for name, _, _ in self.CASES:
            for out in self.outs(name, users):
                self.assertEqual(out["transformedResponse"][name], 0)
                self.assertTrue(out["additionalInfo"]["evaluation"]["passReasons"])

    def test_unanswerable_reads_are_unevaluated(self):
        users = fixture("okta_users_list_synthetic.json")
        full_page = [copy.deepcopy(users[0]) for _ in range(200)]
        no_status = copy.deepcopy(users)
        del no_status[3]["status"]
        bodies = [{}, None, "{}", [], "[]", {"errorCode": "E0000011", "errorSummary": "Invalid token provided"},
                  {"apiResponse": {"errorCode": "E0000047", "errorSummary": "API call exceeded rate limit"}},
                  full_page, no_status, {"apiResponse": users, "paginationTruncated": True}, ["not a user"]]
        for name, _, _ in self.CASES:
            for body in bodies:
                for out in self.outs(name, body):
                    self.assertIsNone(out["transformedResponse"][name], (name, str(body)[:80]))
                    self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "error")


class FastPass(Both, unittest.TestCase):
    NAME = "isOktaFastPassEnabled"
    KEY = NAME

    def posture(self):
        return fixture("okta_authenticator_posture_synthetic.json")

    def test_okta_verify_with_signed_nonce_active_is_true(self):
        self.assertIs(self.value(self.posture(), self.KEY), True)
        self.assertIs(self.value({"result": self.posture()}, self.KEY), True)
        self.assert_measured(self.posture())

    def test_signed_nonce_inactive_or_absent_is_false(self):
        data = self.posture()
        data["authenticatorMethods"][2][1]["status"] = "INACTIVE"
        self.assertIs(self.value(data, self.KEY), False)
        data = self.posture()
        del data["authenticatorMethods"][2][1]
        self.assertIs(self.value(data, self.KEY), False)

    def test_okta_verify_inactive_or_missing_is_false(self):
        data = self.posture()
        data["authenticators"][2]["status"] = "INACTIVE"
        self.assertIs(self.value(data, self.KEY), False)
        data = self.posture()
        del data["authenticators"][2]
        del data["authenticatorMethods"][2]
        self.assertIs(self.value(data, self.KEY), False)

    def test_method_read_refused_is_unevaluated(self):
        data = self.posture()
        data["authenticatorMethods"][2] = {"apiResponse": {"errorCode": "E0000006", "errorSummary": "You do not have permission to perform the requested action"}}
        self.assert_unevaluated(data, self.KEY)
        data = self.posture()
        del data["authenticatorMethods"]
        self.assert_unevaluated(data, self.KEY)
        data = self.posture()
        data["authenticatorMethods"] = data["authenticatorMethods"][:3]
        self.assert_unevaluated(data, self.KEY)

    def test_factor_catalogue_is_not_read_as_authenticators(self):
        catalogue = [{"factorType": "signed_nonce", "provider": "OKTA", "status": "ACTIVE"},
                     {"factorType": "push", "provider": "OKTA", "status": "ACTIVE"}]
        self.assert_unevaluated(catalogue, self.KEY)
        self.assert_unevaluated({"apiResponse": catalogue}, self.KEY)

    def test_no_evidence_bodies_are_unevaluated(self):
        for body in [{}, None, "{}", [], {"errorCode": "E0000011"}, {"authenticators": []}, {"statusCode": 401}]:
            self.assert_unevaluated(body, self.KEY)


if __name__ == "__main__":
    unittest.main()
