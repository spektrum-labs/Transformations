"""isMFAEnforcedForAdmins reads the 'Okta Admin Console' authentication policy from getMfaPolicyRules.

Fixture shape mirrors Spektrum's tenant read of 2026-09-25 (ids replaced): the Admin Console policy
has two ACTIVE ALLOW rules, both ASSURANCE / 2FA.
"""
import copy
import importlib.util
import unittest
from pathlib import Path

PATH = Path(__file__).with_name("ismfaenforcedforadmins.py")
KEY = "isMFAEnforcedForAdmins"


def load():
    spec = importlib.util.spec_from_file_location("ismfaenforcedforadmins", PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def rule(name, mode="2FA", access="ALLOW", status="ACTIVE", kind="ASSURANCE"):
    return {"name": name, "status": status,
            "actions": {"appSignOn": {"access": access, "verificationMethod": {"type": kind, "factorMode": mode}}}}


REAL = {"result": {
    "signOnPolicies": [], "signOnRules": [],
    "accessPolicies": [
        {"id": "rstA", "name": "Okta Admin Console", "status": "ACTIVE"},
        {"id": "rstB", "name": "Okta Account Management Policy", "status": "ACTIVE",
         "_embedded": {"resourceType": "END_USER_ACCOUNT_MANAGEMENT"}},
    ],
    "accessRules": [
        [rule("Admin App Policy"), rule("Catch-all Rule")],
        [rule("Password Expiry Rule", mode="1FA")],
    ],
}}


class AdminMfaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = load()

    def out(self, payload):
        return self.t.transform(payload)["transformedResponse"]

    def test_real_shape_passes_with_counts(self):
        out = self.out(REAL)
        self.assertIs(out[KEY], True)
        self.assertEqual(out["adminConsoleAllowRules"], 2)
        self.assertEqual(out["adminConsoleSingleFactorRules"], 0)

    def test_one_single_factor_rule_fails(self):
        flipped = copy.deepcopy(REAL)
        flipped["result"]["accessRules"][0][1] = rule("Catch-all Rule", mode="1FA")
        out = self.out(flipped)
        self.assertIs(out[KEY], False)
        self.assertEqual(out["adminConsoleSingleFactorRules"], 1)

    def test_unknown_verification_method_fails(self):
        flipped = copy.deepcopy(REAL)
        flipped["result"]["accessRules"][0][0] = rule("Chain", kind="AUTH_METHOD_CHAIN", mode="")
        self.assertIs(self.out(flipped)[KEY], False)

    def test_deny_and_inactive_rules_are_not_judged(self):
        flipped = copy.deepcopy(REAL)
        flipped["result"]["accessRules"][0].append(rule("Blocked", mode="1FA", access="DENY"))
        flipped["result"]["accessRules"][0].append(rule("Old", mode="1FA", status="INACTIVE"))
        self.assertIs(self.out(flipped)[KEY], True)

    def test_no_allow_rule_fails(self):
        flipped = copy.deepcopy(REAL)
        flipped["result"]["accessRules"][0] = [rule("Blocked", access="DENY")]
        self.assertIs(self.out(flipped)[KEY], False)

    def test_other_policies_do_not_count(self):
        flipped = copy.deepcopy(REAL)
        flipped["result"]["accessPolicies"][0]["name"] = "Renamed"
        self.assertIs(self.out(flipped)[KEY], False)

    def test_inactive_admin_policy_fails(self):
        flipped = copy.deepcopy(REAL)
        flipped["result"]["accessPolicies"][0]["status"] = "INACTIVE"
        self.assertIs(self.out(flipped)[KEY], False)

    def test_misaligned_rules_fail(self):
        flipped = copy.deepcopy(REAL)
        flipped["result"]["accessRules"] = flipped["result"]["accessRules"][:1]
        self.assertIs(self.out(flipped)[KEY], False)

    def test_bodies_that_prove_nothing_fail(self):
        for body in [{}, None, "{}", [], {"errorCode": "E0000011", "errorSummary": "Invalid token provided"},
                     {"result": {"errorMessage": "401", "vendorStatus": 401}}, b"not json"]:
            self.assertIs(self.out(body)[KEY], False, body)


if __name__ == "__main__":
    unittest.main()
