"""Google - MFA isAdminMFAPhishingResistant: Directory users.list (admins, isEnforcedIn2Sv) + Cloud Identity
2-Step Verification factor policies (allowedSignInFactorSet). Synthetic bodies in the documented shapes; no
customer data.
"""
import importlib.util
import json
import unittest
from pathlib import Path

KEY = "isAdminMFAPhishingResistant"


def load():
    spec = importlib.util.spec_from_file_location("google_admin_pr", Path(__file__).with_name("isadminmfaphishingresistant.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def user(email, admin=False, delegated=False, enforced=True, suspended=False):
    return {"primaryEmail": email, "isAdmin": str(admin), "isDelegatedAdmin": str(delegated),
            "isEnforcedIn2Sv": str(enforced), "isEnrolledIn2Sv": "True", "suspended": str(suspended),
            "orgUnitPath": "/IT"}


def factor(value, ou="orgUnits/example01"):
    return {"name": "policies/example", "type": "ADMIN", "policyQuery": {"orgUnit": ou, "sortOrder": 1},
            "setting": {"type": "settings/security.two_step_verification_enforcement_factor",
                        "value": {"allowedSignInFactorSet": value}}}


ENFORCEMENT = {"name": "policies/enf", "type": "ADMIN", "policyQuery": {"orgUnit": "orgUnits/example01"},
               "setting": {"type": "settings/security.two_step_verification_enforcement",
                           "value": {"enforcedFrom": "2026-01-01T00:00:00Z"}}}
USERS = {"kind": "admin#directory#users", "users": [
    user("super@example.com", admin=True), user("delegate@example.com", delegated=True),
    user("staff@example.com", enforced=False), user("old-admin@example.com", admin=True, enforced=False, suspended=True)]}


def body(users, policies):
    return {"users": users, "policies": {"policies": policies}}


class GoogleAdminPhishingResistantTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = load()

    def run_(self, payload):
        out = self.t.transform(payload)
        return out["transformedResponse"][KEY], out

    def test_every_policy_passkey_only_and_admins_enforced_is_true(self):
        payload = body(USERS, [ENFORCEMENT, factor("PASSKEY_ONLY"), factor("PASSKEY_ONLY", "orgUnits/example02")])
        for p in (payload, {"apiResponse": payload}, json.dumps(payload)):
            with self.subTest(p=str(p)[:40]):
                value, out = self.run_(p)
                self.assertIs(value, True)
                self.assertEqual(out["additionalInfo"]["transformation"]["inputSummary"]["activeAdmins"], 2)

    def test_no_passkey_only_policy_is_false(self):
        for weak in ("ALL", "NO_TELEPHONY", "PASSKEY_PLUS_SECURITY_CODE", "PASSKEY_PLUS_IP_BOUND_SECURITY_CODE"):
            with self.subTest(weak=weak):
                self.assertIs(self.run_(body(USERS, [ENFORCEMENT, factor(weak), factor("ALL")]))[0], False)

    def test_admin_without_enforcement_is_false(self):
        users = {"users": USERS["users"] + [user("lax@example.com", admin=True, enforced=False)]}
        value, out = self.run_(body(users, [factor("PASSKEY_ONLY")]))
        self.assertIs(value, False)
        self.assertIn("lax@example.com", " ".join(out["additionalInfo"]["evaluation"]["failReasons"]))

    def test_mixed_policies_are_not_evaluated(self):
        value, out = self.run_(body(USERS, [factor("PASSKEY_ONLY"), factor("ALL", "orgUnits/example02")]))
        self.assertIsNone(value)
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "error")

    def test_unreadable_or_incomplete_is_not_evaluated(self):
        no_admins = {"users": [user("staff@example.com")]}
        cases = [None, "", {}, [], {"users": USERS}, {"policies": {"policies": [factor("PASSKEY_ONLY")]}},
                 body(USERS, [ENFORCEMENT]),
                 body(USERS, [factor("SOMETHING_NEW")]),
                 body(no_admins, [factor("PASSKEY_ONLY")]),
                 body(dict(USERS, nextPageToken="next"), [factor("PASSKEY_ONLY")]),
                 {"users": USERS, "policies": {"policies": [factor("PASSKEY_ONLY")], "nextPageToken": "n"}},
                 {"users": {"error": {"code": 403, "message": "Request had insufficient authentication scopes."}},
                  "policies": {"policies": [factor("PASSKEY_ONLY")]}},
                 {"error": True, "message": "Integration execution error: HTTP 403: Forbidden"}]
        for payload in cases:
            with self.subTest(payload=str(payload)[:70]):
                value, out = self.run_(payload)
                self.assertIsNone(value)
                self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "error")


if __name__ == "__main__":
    unittest.main()
