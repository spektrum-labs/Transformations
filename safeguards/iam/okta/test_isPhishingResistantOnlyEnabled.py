"""isPhishingResistantOnlyEnabled reads GET /api/v1/org/factors (listOrgFactors).

REAL mirrors a customer tenant read of 2026-09-30 12:53 ET (factorType/provider/status only, nothing else
kept): a YubiKey OTP token, Okta Verify push, a security question, TOTP and SMS are ACTIVE; every
phishing-resistant type is INACTIVE. It must read False.
"""
import copy
import importlib.util
import json
import unittest
from pathlib import Path

PATH = Path(__file__).with_name("isPhishingResistantOnlyEnabled.py")
KEY = "isPhishingResistantOnlyEnabled"


ROOT = PATH.resolve().parents[3]


def load():
    spec = importlib.util.spec_from_file_location("isPhishingResistantOnlyEnabled", PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SandboxModule:
    """The same file compiled as Token-Service runs it (RestrictedPython replica in tools/)."""

    def __init__(self):
        spec = importlib.util.spec_from_file_location("restricted_sandbox_okta_pro", ROOT / "tools" / "restricted_sandbox.py")
        sandbox = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(sandbox)
        self.transform = sandbox.load(PATH.read_text(), "<transformation>")["transform"]


def f(kind, provider, status):
    return {"factorType": kind, "provider": provider, "status": status}


REAL = [
    f("token", "RSA", "NOT_SETUP"), f("token:hardware", "YUBICO", "ACTIVE"), f("token", "SYMANTEC", "NOT_SETUP"),
    f("smart_card", "SMART_CARD", "INACTIVE"), f("token:hotp", "CUSTOM", "NOT_SETUP"), f("call", "OKTA", "INACTIVE"),
    f("token:software:totp", "OKTA", "ACTIVE"), f("sms", "OKTA", "ACTIVE"), f("signed_nonce", "OKTA", "INACTIVE"),
    f("email", "OKTA", "INACTIVE"), f("question", "OKTA", "ACTIVE"), f("push", "OKTA", "ACTIVE"),
    f("u2f", "FIDO", "INACTIVE"), f("webauthn", "FIDO", "INACTIVE"), f("web", "DUO", "NOT_SETUP"),
    f("token:software:totp", "GOOGLE", "INACTIVE"), f("token", "CUSTOM", "NOT_SETUP"),
]


def only(*kinds):
    body = [dict(x, status="INACTIVE") if x["status"] == "ACTIVE" else dict(x) for x in REAL]
    for x in body:
        if x["factorType"] in kinds:
            x["status"] = "ACTIVE"
    return body


class PhishResistantOnlyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = load()

    def out(self, payload):
        return self.t.transform(payload)["transformedResponse"]

    def assert_unevaluated(self, payload):
        res = self.t.transform(payload)
        self.assertIsNone(res["transformedResponse"][KEY])
        self.assertEqual(res["additionalInfo"]["dataCollection"]["status"], "error")

    def test_real_phishable_only_fails(self):
        res = self.t.transform(REAL)
        out = res["transformedResponse"]
        self.assertIs(out[KEY], False)
        self.assertEqual(out["phishResistantActiveCount"], 0)
        self.assertEqual(out["phishableActiveCount"], 5)
        self.assertEqual(res["additionalInfo"]["dataCollection"]["status"], "success")
        self.assertTrue(res["additionalInfo"]["evaluation"]["failReasons"])

    def test_wrappers_and_string_read_the_same(self):
        for body in ({"apiResponse": REAL}, {"response": {"apiResponse": REAL}}, json.dumps(REAL),
                     json.dumps(REAL).encode("utf-8"), {"data": REAL, "validation": {"status": "unknown"}}):
            with self.subTest(body=str(body)[:40]):
                self.assertIs(self.out(body)[KEY], False)

    def test_only_resistant_active_passes(self):
        out = self.out(only("webauthn", "signed_nonce"))
        self.assertIs(out[KEY], True)
        self.assertEqual(out["phishableActiveCount"], 0)

    def test_each_resistant_type_alone_passes(self):
        for kind in ("webauthn", "u2f", "signed_nonce", "smart_card"):
            with self.subTest(kind=kind):
                self.assertIs(self.out(only(kind))[KEY], True)

    def test_resistant_plus_any_phishable_fails(self):
        # isAdminMFAPhishingResistant reads this mix as None (admin policy may narrow it); the org-wide key fails.
        for phish in ("push", "sms", "call", "email", "question", "token:software:totp", "token:hotp",
                      "token", "token:hardware", "web"):
            with self.subTest(phish=phish):
                out = self.out(only("webauthn", phish))
                self.assertIs(out[KEY], False)
                self.assertEqual(out["phishResistantActiveCount"], 1)

    def test_yubikey_otp_is_not_resistant(self):
        self.assertIs(self.out(only("token:hardware"))[KEY], False)

    def test_nothing_active_fails(self):
        self.assertIs(self.out(only())[KEY], False)

    def test_does_not_mutate_input(self):
        body = copy.deepcopy(REAL)
        self.t.transform(body)
        self.assertEqual(body, REAL)

    def test_no_evidence_bodies_are_not_evaluated(self):
        for body in (None, {}, [], "", "null", "not json", b"", {"errorCode": "E0000011", "errorSummary": "Invalid token"},
                     {"status": 401, "error": "Unauthorized"}, {"items": [{"id": 1}]}, [{"id": "x"}],
                     [f("push", "OKTA", "ACTIVE"), {"unrelated": True}], [f("webauthn", "FIDO", "active")],
                     {"apiResponse": {}}, {"apiResponse": []}, 42):
            with self.subTest(body=body):
                self.assert_unevaluated(body)


try:
    import RestrictedPython  # noqa: F401

    class PhishResistantOnlySandboxTests(PhishResistantOnlyTests):
        @classmethod
        def setUpClass(cls):
            cls.t = SandboxModule()
except ImportError:  # CI installs RestrictedPython from requirements-test.txt
    pass


if __name__ == "__main__":
    unittest.main()
