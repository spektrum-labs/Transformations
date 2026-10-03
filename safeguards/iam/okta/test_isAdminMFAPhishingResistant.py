"""isAdminMFAPhishingResistant reads GET /api/v1/org/factors (listOrgFactors).

REAL mirrors a customer tenant read of 2026-09-29 (factorType/provider/status only, nothing else kept):
TOTP and Okta Verify push are ACTIVE, every phishing-resistant type is INACTIVE.
"""
import copy
import importlib.util
import json
import unittest
from pathlib import Path

PATH = Path(__file__).with_name("isAdminMFAPhishingResistant.py")
KEY = "isAdminMFAPhishingResistant"


def load():
    spec = importlib.util.spec_from_file_location("isAdminMFAPhishingResistant", PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def f(kind, provider, status):
    return {"factorType": kind, "provider": provider, "status": status}


REAL = [
    f("token", "RSA", "NOT_SETUP"), f("token:hardware", "YUBICO", "NOT_SETUP"), f("token", "SYMANTEC", "NOT_SETUP"),
    f("smart_card", "SMART_CARD", "INACTIVE"), f("token:hotp", "CUSTOM", "NOT_SETUP"), f("call", "OKTA", "INACTIVE"),
    f("token:software:totp", "OKTA", "ACTIVE"), f("sms", "OKTA", "INACTIVE"), f("signed_nonce", "OKTA", "INACTIVE"),
    f("email", "OKTA", "INACTIVE"), f("question", "OKTA", "INACTIVE"), f("push", "OKTA", "ACTIVE"),
    f("u2f", "FIDO", "INACTIVE"), f("webauthn", "FIDO", "INACTIVE"), f("web", "DUO", "NOT_SETUP"),
    f("token:software:totp", "GOOGLE", "INACTIVE"),
]


def only_resistant():
    body = [dict(x, status="INACTIVE") if x["status"] == "ACTIVE" else dict(x) for x in REAL]
    for x in body:
        if x["factorType"] in ("webauthn", "signed_nonce"):
            x["status"] = "ACTIVE"
    return body


class AdminPhishResistantTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = load()

    def run_t(self, payload):
        return self.t.transform(payload)

    def out(self, payload):
        return self.run_t(payload)["transformedResponse"]

    def assert_unevaluated(self, payload):
        res = self.run_t(payload)
        self.assertIsNone(res["transformedResponse"][KEY])
        self.assertEqual(res["additionalInfo"]["dataCollection"]["status"], "error")

    def test_real_no_resistant_factor_fails_with_counts(self):
        out = self.out(REAL)
        self.assertIs(out[KEY], False)
        self.assertEqual(out["phishResistantActiveCount"], 0)
        self.assertEqual(out["phishableActiveCount"], 2)

    def test_legacy_wrappers_read_the_same(self):
        self.assertIs(self.out({"apiResponse": REAL})[KEY], False)
        self.assertIs(self.out({"response": {"apiResponse": REAL}})[KEY], False)
        self.assertIs(self.out(json.dumps(REAL))[KEY], False)

    def test_only_resistant_active_passes(self):
        out = self.out(only_resistant())
        self.assertIs(out[KEY], True)
        self.assertEqual(out["phishResistantActiveCount"], 2)
        self.assertEqual(out["phishableActiveCount"], 0)

    def test_resistant_plus_phishable_is_not_evaluated(self):
        # the old transform passed here: WebAuthn ACTIVE next to push and TOTP
        mixed = copy.deepcopy(REAL)
        for x in mixed:
            if x["factorType"] == "webauthn":
                x["status"] = "ACTIVE"
        self.assert_unevaluated(mixed)

    def test_u2f_and_fastpass_count_as_resistant(self):
        for kind in ("u2f", "signed_nonce", "smart_card"):
            body = [dict(x, status="INACTIVE") for x in REAL]
            for x in body:
                if x["factorType"] == kind:
                    x["status"] = "ACTIVE"
            self.assertIs(self.out(body)[KEY], True, kind)

    def test_yubikey_otp_is_not_resistant(self):
        body = [dict(x, status="INACTIVE") for x in REAL]
        body[1]["status"] = "ACTIVE"  # token:hardware / YUBICO (OTP)
        self.assertIs(self.out(body)[KEY], False)

    def test_no_evidence_bodies_are_not_evaluated(self):
        for body in (None, {}, [], "", "null", {"errorCode": "E0000011", "errorSummary": "Invalid token provided"},
                     {"status": 401, "error": "Unauthorized"}, {"items": [{"id": 1}]}, [{"id": "x"}],
                     [f("push", "OKTA", "ACTIVE"), {"unrelated": True}], {"apiResponse": {}}):
            with self.subTest(body=body):
                self.assert_unevaluated(body)


if __name__ == "__main__":
    unittest.main()
