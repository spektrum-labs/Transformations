"""isAdminMFAPhishingResistant judged from the Okta Admin Console app's authentication policy (workflow
isAdminMFAPhishingResistant: applications, accessPolicies, accessRules). Synthetic ids and names in the shape of the
Okta Apps and Policy APIs."""
import copy
import importlib.util
import unittest
from pathlib import Path

HERE = Path(__file__).parent
ROOT = HERE.resolve().parents[2]
KEY = "isAdminMFAPhishingResistant"
BASE = "https://example.okta.com/api/v1/policies/"


def load():
    spec = importlib.util.spec_from_file_location("okta_admin_console_policy", HERE / "isAdminMFAPhishingResistantPolicy.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def sandboxed():
    spec = importlib.util.spec_from_file_location("restricted_sandbox_okta_admin_console", ROOT / "tools" / "restricted_sandbox.py")
    sandbox = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sandbox)
    return sandbox.load((HERE / "isAdminMFAPhishingResistantPolicy.py").read_text(), "<transformation>")["transform"]


def app(name, policy):
    return {"id": "0oa" + name, "name": name, "label": name, "status": "ACTIVE", "signOnMode": "OPENID_CONNECT",
            "_links": {"accessPolicy": {"href": BASE + policy}}}


def assurance(mode="2FA", resistant="REQUIRED", uv="OPTIONAL", required=True):
    return {"type": "ASSURANCE", "factorMode": mode, "reauthenticateIn": "PT12H",
            "constraints": [{"knowledge": {"required": True, "types": ["password"]},
                             "possession": {"required": required, "phishingResistant": resistant,
                                            "userVerification": uv}}]}


def rule(name, method, access="ALLOW", status="ACTIVE", system=False):
    return {"id": "rul" + name, "name": name, "status": status, "system": system,
            "actions": {"appSignOn": {"access": access, "verificationMethod": method}}}


def policy(pid, name, system=False):
    return {"id": pid, "name": name, "status": "ACTIVE", "system": system, "_embedded": {"resourceType": "APP"}}


REAL = {"result": {
    "applications": [app("okta_enduser", "rstDASH"), app("saasure", "rstADMIN"), app("example_app", "rstDEFAULT")],
    "accessPolicies": [policy("rstADMIN", "Okta Admin Console"), policy("rstDASH", "Okta Dashboard"),
                       policy("rstDEFAULT", "Default Policy", True)],
    "accessRules": [
        [rule("Admins", assurance(uv="REQUIRED")), rule("Catch-all Rule", assurance(), system=True)],
        [rule("Catch-all Rule", assurance(resistant=None), system=True)],
        [rule("Catch-all Rule", assurance(mode="1FA", resistant=None), system=True)],
    ],
}}


class AdminConsolePolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runs = [load(), sandboxed()]

    def check(self, body, expected):
        for transform in self.runs:
            full = transform(copy.deepcopy(body))
            self.assertIs(full["transformedResponse"][KEY], expected)
            self.assertEqual(full["additionalInfo"]["dataCollection"]["status"], "error" if expected is None else "success")
        return full

    def edit(self, index, value):
        data = copy.deepcopy(REAL)
        data["result"]["accessRules"][0][index] = value
        return data

    def test_real_shape_admin_console_requires_phishing_resistant_mfa(self):
        full = self.check(REAL, True)
        self.assertEqual(full["transformedResponse"]["phishingResistantRules"], 2)
        self.assertIn("Okta Admin Console", full["additionalInfo"]["evaluation"]["passReasons"][0])

    def test_flipped_catch_all_without_phishing_resistance_fails(self):
        full = self.check(self.edit(1, rule("Catch-all Rule", assurance(resistant=None), system=True)), False)
        self.assertTrue(full["additionalInfo"]["evaluation"]["recommendations"])
        self.check(self.edit(1, rule("Catch-all Rule", assurance(mode="1FA"), system=True)), False)
        self.check(self.edit(1, rule("Catch-all Rule", assurance(required=False), system=True)), False)
        no_constraints = assurance()
        del no_constraints["constraints"]
        self.check(self.edit(1, rule("Catch-all Rule", no_constraints, system=True)), False)

    def test_string_required_false_fails_closed(self):
        for value in ["false", "False"]:
            self.check(self.edit(1, rule("Catch-all Rule", assurance(required=value), system=True)), False)

    def test_smart_card_chain_is_card_plus_pin(self):
        card = {"key": "smart_card_idp", "method": "smart_card_idp"}
        self.check(self.edit(0, rule("Admins", {"type": "AUTH_METHOD_CHAIN", "chains": [{"authenticationMethods": [card]}]})), True)

    def test_one_factor_with_user_verification_is_phishing_resistant_mfa(self):
        self.check(self.edit(1, rule("Catch-all Rule", assurance(mode="1FA", uv="REQUIRED"), system=True)), True)

    def test_other_policies_and_deny_or_inactive_rules_do_not_count(self):
        data = copy.deepcopy(REAL)
        data["result"]["accessRules"][0].insert(0, rule("Blocked", assurance(resistant=None), access="DENY"))
        data["result"]["accessRules"][0].insert(0, rule("Old", assurance(resistant=None), status="INACTIVE"))
        self.check(data, True)

    def test_policy_is_found_by_the_app_link_not_by_name(self):
        data = copy.deepcopy(REAL)
        data["result"]["accessPolicies"][0]["name"] = "Renamed"
        self.check(data, True)
        data = copy.deepcopy(REAL)
        data["result"]["applications"][1]["_links"]["accessPolicy"]["href"] = BASE + "rstDASH"
        self.check(data, False)  # the console now signs in under the dashboard policy

    def test_auth_method_chain_rules(self):
        fido = {"key": "webauthn", "method": "webauthn", "userVerification": "REQUIRED"}
        push = {"key": "okta_verify", "method": "push"}
        pw = {"key": "okta_password", "method": "password"}
        good = {"type": "AUTH_METHOD_CHAIN", "chains": [{"authenticationMethods": [pw], "next": [{"authenticationMethods": [fido]}]}]}
        self.check(self.edit(0, rule("Admins", good)), True)
        self.check(self.edit(0, rule("Admins", {"type": "AUTH_METHOD_CHAIN", "chains": [{"authenticationMethods": [fido]}]})), True)
        bad = {"type": "AUTH_METHOD_CHAIN", "chains": [{"authenticationMethods": [pw], "next": [{"authenticationMethods": [push]}]}]}
        self.check(self.edit(0, rule("Admins", bad)), False)
        mixed = {"type": "AUTH_METHOD_CHAIN", "chains": [{"authenticationMethods": [pw], "next": [{"authenticationMethods": [fido, push]}]}]}
        self.check(self.edit(0, rule("Admins", mixed)), False)
        self.check(self.edit(0, rule("Admins", {"type": "AUTH_METHOD_CHAIN", "chains": [{"authenticationMethods": [{"key": "x"}]}]})), None)
        self.check(self.edit(0, rule("Admins", {"type": "AUTH_METHOD_CHAIN"})), None)

    def test_unreadable_method_is_not_evaluated_unless_a_rule_already_fails(self):
        self.check(self.edit(0, rule("Admins", {"type": "ID_PROOFING"})), None)
        data = self.edit(0, rule("Admins", {"type": "ID_PROOFING"}))
        data["result"]["accessRules"][0][1] = rule("Catch-all Rule", assurance(resistant=None), system=True)
        self.check(data, False)

    def test_missing_app_policy_or_cut_lists_are_not_evaluated(self):
        data = copy.deepcopy(REAL)
        data["result"]["applications"] = data["result"]["applications"][:1]
        self.check(data, None)
        data = copy.deepcopy(REAL)
        del data["result"]["applications"][1]["_links"]
        self.check(data, None)
        data = copy.deepcopy(REAL)
        data["result"]["accessPolicies"][0]["id"] = "rstOTHER"
        self.check(data, None)
        data = copy.deepcopy(REAL)
        data["result"]["accessRules"][0] = data["result"]["accessRules"][0][:1]  # Catch-all Rule missing
        self.check(data, None)
        data = copy.deepcopy(REAL)
        data["result"]["accessRules"] = data["result"]["accessRules"][:2]
        self.check(data, None)
        data = copy.deepcopy(REAL)
        data["result"]["accessPolicies"][0]["status"] = "INACTIVE"
        self.check(data, None)
        data = self.edit(0, rule("Admins", assurance(), access="DENY"))
        data["result"]["accessRules"][0][1] = rule("Catch-all Rule", assurance(), access="DENY", system=True)
        self.check(data, None)

    def test_hidden_admin_console_app_is_coded_not_available(self):
        # An OAuth service app cannot see the Admin Console app: a list without it, or an empty filtered list.
        data = copy.deepcopy(REAL)
        data["result"]["applications"] = [a for a in data["result"]["applications"] if a["name"] != "saasure"]
        for body in [data, {"applications": [], "accessPolicies": [], "accessRules": []}]:
            for transform in self.runs:
                out = transform(copy.deepcopy(body))
                self.assertIsNone(out["transformedResponse"][KEY])
                collection = out["additionalInfo"]["dataCollection"]
                self.assertEqual(collection["status"], "error")
                self.assertEqual(collection["errorCode"], "not_available")
                self.assertTrue(collection["errors"][0].startswith("NOT-AVAILABLE:"))
                self.assertIn("OAuth service app cannot see the Admin Console app", collection["errors"][0])
                self.assertNotIn("Classic Engine", collection["errors"][0])

    def test_app_list_cut_short_is_not_available_free(self):
        data = copy.deepcopy(REAL)
        data["result"]["applications"] = [app("filler" + str(i), "rstDEFAULT") for i in range(200)]
        for transform in self.runs:
            collection = transform(copy.deepcopy(data))["additionalInfo"]["dataCollection"]
            self.assertEqual(collection["status"], "error")
            self.assertNotIn("errorCode", collection)
            self.assertIn("cut short", collection["errors"][0])

    def test_other_not_evaluated_paths_carry_no_error_code(self):
        data = copy.deepcopy(REAL)
        del data["result"]["applications"][1]["_links"]
        for body in [data, {"applications": None}, {"errorCode": "E0000006", "errorSummary": "denied"}]:
            for transform in self.runs:
                self.assertNotIn("errorCode", transform(copy.deepcopy(body))["additionalInfo"]["dataCollection"])

    def test_empty_none_and_error_bodies_are_not_evaluated(self):
        for body in [{"applications": None, "accessPolicies": None},
                     {"applications": [], "accessPolicies": [], "accessRules": []},
                     {"applications": {"errorCode": "E0000006"}, "accessPolicies": [], "accessRules": []},
                     {"errorCode": "E0000006", "errorSummary": "denied", "applications": [], "accessPolicies": []}]:
            self.check(body, None)

    def test_every_outcome_carries_the_same_keys(self):
        flipped = self.edit(1, rule("Catch-all Rule", assurance(resistant=None), system=True))
        for body, expected in [(REAL, True), (flipped, False), ({"applications": [], "accessPolicies": [], "accessRules": []}, None),
                               ({"errorCode": "E0000006", "errorSummary": "denied"}, None), ("not json", None)]:
            for transform in self.runs:
                out = transform(copy.deepcopy(body) if not isinstance(body, str) else body)["transformedResponse"]
                self.assertEqual(sorted(out), ["isAdminMFAPhishingResistant", "phishingResistantRules", "weakRules"])
                self.assertIs(out[KEY], expected)
                self.assertEqual(out["weakRules"] is None, expected is None)

    def test_filtered_single_app_list_is_enough(self):
        data = copy.deepcopy(REAL)
        data["result"]["applications"] = [data["result"]["applications"][1]]
        self.check(data, True)


if __name__ == "__main__":
    unittest.main()
