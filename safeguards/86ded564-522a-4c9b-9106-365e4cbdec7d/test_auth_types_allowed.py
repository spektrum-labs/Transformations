"""authTypesAllowed reads the Okta org factor catalogue (GET /api/v1/org/factors).

It passes only when every ACTIVE factorType is on the allowlist. The allowlist omitted
token:hardware and smart_card, so a hardware OTP token and a PIV/CAC smart card were counted as
violations alongside SMS.

MOTUS mirrors a real customer read of 2026-10-05 (factorType/provider/status only): a YubiKey,
Okta Verify push, TOTP, SMS and a security question are ACTIVE. The stored failReason was
"Authentication types that are not allowed are active: token:hardware, sms, question". After this
change the YubiKey must drop out of that list, while sms and question must remain -- the fix must
narrow the complaint without clearing a failure that is real.
"""
import importlib.util
import json
import unittest
from pathlib import Path

PATH = Path(__file__).with_name("auth_types_allowed.py")
KEY = "authTypesAllowed"

ROOT = PATH.resolve().parents[2]


def load():
    spec = importlib.util.spec_from_file_location("auth_types_allowed", PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SandboxModule:
    """The same file compiled as Token-Service runs it (RestrictedPython replica in tools/)."""

    def __init__(self):
        spec = importlib.util.spec_from_file_location(
            "restricted_sandbox_auth_types_allowed", ROOT / "tools" / "restricted_sandbox.py"
        )
        sandbox = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(sandbox)
        self.transform = sandbox.load(PATH.read_text(), "<transformation>")["transform"]


def f(kind, provider, status):
    return {"factorType": kind, "provider": provider, "status": status}


# Motus LLC, 2026-10-05. The five ACTIVE rows; catalogue rows that were INACTIVE/NOT_SETUP omitted.
MOTUS = [
    f("token:hardware", "YUBICO", "ACTIVE"),
    f("push", "OKTA", "ACTIVE"),
    f("token:software:totp", "OKTA", "ACTIVE"),
    f("sms", "OKTA", "ACTIVE"),
    f("question", "OKTA", "ACTIVE"),
]


def verdict(response):
    return response["transformedResponse"][KEY]


def reasons(response):
    ev = response["additionalInfo"]["evaluation"]
    return " ".join(ev["passReasons"] + ev["failReasons"])


def summary(response):
    return response["additionalInfo"]["transformation"]["inputSummary"]


class HardwareTokensAndSmartCardsAreNotViolations(unittest.TestCase):
    def setUp(self):
        self.transform = load().transform

    def test_a_yubikey_alone_passes(self):
        self.assertTrue(verdict(self.transform([f("token:hardware", "YUBICO", "ACTIVE")])))

    def test_a_smart_card_alone_passes(self):
        self.assertTrue(verdict(self.transform([f("smart_card", "SMART_CARD", "ACTIVE")])))

    def test_smart_card_agrees_with_the_phishing_resistant_sibling(self):
        """isPhishingResistantOnlyEnabled treats smart_card as phishing-resistant; so must this."""
        sibling = ROOT / "safeguards" / "iam" / "okta" / "isPhishingResistantOnlyEnabled.py"
        self.assertIn("smart_card", sibling.read_text())
        allowed = load().ALLOWED_FACTOR_TYPES
        for kind in ("webauthn", "u2f", "signed_nonce", "smart_card"):
            self.assertIn(kind, allowed, kind + " is phishing-resistant and must be allowed")

    def test_hardware_token_with_an_authenticator_app_passes(self):
        body = [f("token:hardware", "YUBICO", "ACTIVE"), f("token:software:totp", "OKTA", "ACTIVE")]
        self.assertTrue(verdict(self.transform(body)))


class TheMotusRegression(unittest.TestCase):
    """The fix must narrow the complaint, not clear the failure."""

    def setUp(self):
        self.transform = load().transform

    def test_motus_still_fails(self):
        self.assertFalse(verdict(self.transform(MOTUS)))

    def test_the_yubikey_is_no_longer_named_as_a_violation(self):
        self.assertNotIn("token:hardware", reasons(self.transform(MOTUS)))

    def test_sms_and_question_are_still_named(self):
        text = reasons(self.transform(MOTUS))
        self.assertIn("sms", text)
        self.assertIn("question", text)

    def test_the_counts_move_by_exactly_the_hardware_token(self):
        """Was {total 5, secure 2, insecure 3}; the YubiKey moves from insecure to secure."""
        got = summary(self.transform(MOTUS))
        self.assertEqual(got["totalAuthTypes"], 5)
        self.assertEqual(got["secureAuthTypes"], 3)
        self.assertEqual(got["insecureAuthTypes"], 2)


class TheIntendedFailuresStillFail(unittest.TestCase):
    """sms, call, email and question are what this check exists to catch."""

    def setUp(self):
        self.transform = load().transform

    def test_each_phishable_factor_fails_on_its_own(self):
        for kind in ("sms", "call", "email", "question"):
            body = [f(kind, "OKTA", "ACTIVE"), f("webauthn", "FIDO", "ACTIVE")]
            self.assertFalse(verdict(self.transform(body)), kind + " must fail")

    def test_unrecognised_factors_still_fail(self):
        """token, token:hotp and web are deliberately not allowlisted."""
        for kind in ("token", "token:hotp", "web"):
            body = [f(kind, "RSA", "ACTIVE"), f("webauthn", "FIDO", "ACTIVE")]
            self.assertFalse(verdict(self.transform(body)), kind + " must not pass unexamined")

    def test_inactive_weak_factors_do_not_fail_the_check(self):
        body = [f("sms", "OKTA", "INACTIVE"), f("token:hardware", "YUBICO", "ACTIVE")]
        self.assertTrue(verdict(self.transform(body)))


class UnreadableBodiesDoNotPass(unittest.TestCase):
    def setUp(self):
        self.transform = load().transform

    def test_empty_list(self):
        self.assertFalse(verdict(self.transform([])))

    def test_empty_dict(self):
        self.assertFalse(verdict(self.transform({})))

    def test_nothing_active(self):
        self.assertFalse(verdict(self.transform([f("sms", "OKTA", "INACTIVE")])))


class RunsUnderTheSandbox(unittest.TestCase):
    def setUp(self):
        self.transform = SandboxModule().transform

    def test_motus_still_fails(self):
        self.assertFalse(verdict(self.transform(MOTUS)))

    def test_yubikey_passes(self):
        self.assertTrue(verdict(self.transform([f("token:hardware", "YUBICO", "ACTIVE")])))

    def test_smart_card_passes(self):
        self.assertTrue(verdict(self.transform([f("smart_card", "SMART_CARD", "ACTIVE")])))

    def test_sms_fails(self):
        self.assertFalse(verdict(self.transform([f("sms", "OKTA", "ACTIVE")])))


if __name__ == "__main__":
    unittest.main()
