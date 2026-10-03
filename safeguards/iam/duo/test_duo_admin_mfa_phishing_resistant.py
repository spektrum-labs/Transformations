"""Duo isAdminMFAPhishingResistant: GET /admin/v1/admins/allowed_auth_methods decides; getAdmins only adds findings.

Synthetic bodies in the documented shapes (Duo Admin API "Retrieve Administrator Authentication Factors" and
"Retrieve Administrators"). No customer data.
"""
import importlib.util
import json
import unittest
from pathlib import Path

KEY = "isAdminMFAPhishingResistant"
WEBAUTHN_ONLY = {"hardware_token_enabled": False, "mobile_otp_enabled": False, "push_enabled": False,
                 "sms_enabled": False, "verified_push_enabled": False, "verified_push_length": None,
                 "voice_enabled": False, "webauthn_enabled": True, "yubikey_enabled": False}
DOC_EXAMPLE = {"hardware_token_enabled": True, "mobile_otp_enabled": True, "push_enabled": True,
               "sms_enabled": False, "verified_push_enabled": False, "verified_push_length": None,
               "voice_enabled": False, "webauthn_enabled": True, "yubikey_enabled": True}
ADMINS = {"response": [
    {"admin_id": "DEXAMPLE0000000001", "email": "owner@example.com", "role": "Owner", "status": "Active",
     "webauthncredentials": [{"credential_name": "key-1"}], "phone_details": []},
    {"admin_id": "DEXAMPLE0000000002", "email": "helpdesk@example.com", "role": "Help Desk", "status": "Active",
     "webauthncredentials": [], "phone_details": [{"capabilities": ["push", "sms"]}]},
    {"admin_id": "DEXAMPLE0000000003", "email": "gone@example.com", "role": "Read-only", "status": "Disabled",
     "webauthncredentials": []},
]}


def load():
    spec = importlib.util.spec_from_file_location("duo_admin_pr", Path(__file__).with_name(KEY + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def stringify(flags):
    """Integration-Service can hand Duo booleans over as the strings "True"/"False"."""
    return {k: (str(v) if isinstance(v, bool) else v) for k, v in flags.items()}


class DuoAdminPhishingResistantTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = load()

    def run_(self, payload):
        out = self.t.transform(payload)
        return out["transformedResponse"][KEY], out

    def test_webauthn_only_is_true(self):
        for payload in ({"allowedAuthMethods": {"response": WEBAUTHN_ONLY}, "admins": ADMINS},
                        {"allowedAuthMethods": {"response": stringify(WEBAUTHN_ONLY)}, "admins": ADMINS},
                        {"apiResponse": {"allowedAuthMethods": {"response": WEBAUTHN_ONLY}}},
                        {"response": WEBAUTHN_ONLY},
                        json.dumps({"allowedAuthMethods": {"response": WEBAUTHN_ONLY}})):
            with self.subTest(payload=str(payload)[:60]):
                value, out = self.run_(payload)
                self.assertIs(value, True)
                self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")

    def test_admin_without_key_is_a_finding_not_a_verdict(self):
        value, out = self.run_({"allowedAuthMethods": {"response": WEBAUTHN_ONLY}, "admins": ADMINS})
        self.assertIs(value, True)
        summary = out["additionalInfo"]["transformation"]["inputSummary"]
        self.assertEqual((summary["activeAdmins"], summary["activeAdminsWithoutWebAuthn"]), (2, 1))
        self.assertTrue(out["additionalInfo"]["evaluation"]["additionalFindings"])

    def test_each_phishable_method_alone_makes_it_false(self):
        for key in ("push_enabled", "verified_push_enabled", "sms_enabled", "voice_enabled", "mobile_otp_enabled",
                    "hardware_token_enabled", "yubikey_enabled"):
            flags = dict(WEBAUTHN_ONLY, **{key: True})
            with self.subTest(key=key):
                value, out = self.run_({"allowedAuthMethods": {"response": flags}, "admins": ADMINS})
                self.assertIs(value, False)
                value, out = self.run_({"allowedAuthMethods": {"response": stringify(flags)}})
                self.assertIs(value, False)

    def test_documented_example_and_no_webauthn_are_false(self):
        self.assertIs(self.run_({"allowedAuthMethods": {"response": DOC_EXAMPLE}})[0], False)
        none_strong = dict(WEBAUTHN_ONLY, webauthn_enabled=False)
        value, out = self.run_({"allowedAuthMethods": {"response": none_strong}})
        self.assertIs(value, False)
        self.assertIn("WebAuthn", " ".join(out["additionalInfo"]["evaluation"]["failReasons"]))

    def test_unreadable_or_incomplete_is_not_evaluated(self):
        partial = {k: v for k, v in WEBAUTHN_ONLY.items() if k != "yubikey_enabled"}
        odd = dict(WEBAUTHN_ONLY, sms_enabled="maybe")
        for payload in (None, "", {}, [], {"response": {}}, {"admins": ADMINS},
                        {"allowedAuthMethods": {"response": partial}},
                        {"allowedAuthMethods": {"response": odd}},
                        {"allowedAuthMethods": {"stat": "FAIL", "code": 40301, "message": "Access forbidden"}},
                        {"stat": "FAIL", "code": 40301, "message": "Access forbidden"},
                        {"error": True, "message": "Integration execution error: HTTP 403: Forbidden"},
                        {"statusCode": 403, "message": "Forbidden"}):
            with self.subTest(payload=str(payload)[:70]):
                value, out = self.run_(payload)
                self.assertIsNone(value)
                self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "error")


if __name__ == "__main__":
    unittest.main()
