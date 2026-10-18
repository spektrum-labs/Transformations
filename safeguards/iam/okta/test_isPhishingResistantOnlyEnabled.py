"""isPhishingResistantOnlyEnabled reads GET /api/v1/org/factors (listOrgFactors), or the Identity Engine
authenticators (getAuthenticatorPosture) when the input carries them.

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
        out = self.out(only("webauthn", "u2f"))
        self.assertIs(out[KEY], True)
        self.assertEqual(out["phishableActiveCount"], 0)

    def test_each_resistant_type_alone_passes(self):
        for kind in ("webauthn", "u2f", "smart_card"):
            with self.subTest(kind=kind):
                self.assertIs(self.out(only(kind))[KEY], True)

    def test_fastpass_never_passes(self):
        # review HIGH: the factor list cannot show FastPass phishing-resistant mode
        for kinds in (("signed_nonce",), ("signed_nonce", "webauthn"), ("signed_nonce", "u2f", "smart_card")):
            with self.subTest(kinds=kinds):
                res = self.t.transform(only(*kinds))
                self.assertIsNone(res["transformedResponse"][KEY])
                self.assertEqual(res["additionalInfo"]["dataCollection"]["status"], "error")
        self.assertIs(self.out(only("signed_nonce", "push"))[KEY], False)

    def test_truncated_list_is_not_evaluated(self):
        # review MEDIUM: a list that lacks factors every org lists is a partial read
        for body in ([f("webauthn", "FIDO", "ACTIVE")],
                     [x for x in only("webauthn") if x["factorType"] != "push"],
                     [x for x in only("webauthn") if x["factorType"] not in ("sms", "token:software:totp")]):
            with self.subTest(n=len(body)):
                self.assert_unevaluated(body)

    def test_pagination_marker_is_not_evaluated(self):
        page = only("webauthn")
        for body in ({"apiResponse": page, "nextPage": "https://x.okta.com/api/v1/org/factors?after=abc"},
                     {"apiResponse": page, "_links": {"next": {"href": "https://x"}}},
                     {"response": {"apiResponse": page, "hasMore": True}},
                     {"apiResponse": page, "headers": {"link": '<https://x?after=1>; rel="next"'}},
                     {"data": {"apiResponse": page, "next": "abc"}, "validation": {"status": "unknown"}}):
            with self.subTest(body=str(body)[:50]):
                self.assert_unevaluated(body)
        self.assertIs(self.out({"apiResponse": page, "_links": {"self": {"href": "https://x"}}})[KEY], True)

    def test_failed_validation_is_not_evaluated(self):
        # review MEDIUM: an enriched input whose validation failed is not evidence
        for status in ("failed", "FAILED"):
            with self.subTest(status=status):
                self.assert_unevaluated({"data": only("webauthn"), "validation": {"status": status, "errors": ["x"]}})
        self.assertIs(self.out({"data": only("webauthn"), "validation": {"status": "passed"}})[KEY], True)

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


def auth(key, typ, name, status, allowed=None):
    a = {"id": "aut" + key, "key": key, "type": typ, "name": name, "status": status}
    if allowed:
        a["settings"] = {"allowedFor": allowed}
    return a


def m(typ, status):
    return {"type": typ, "status": status}


def posture(verify=("push:INACTIVE", "totp:ACTIVE", "signed_nonce:ACTIVE"), email="recovery", phone="INACTIVE"):
    """Synthetic getAuthenticatorPosture body: Identity Engine org whose Classic factor list still shows SMS ACTIVE."""
    return {
        "authenticators": [
            auth("okta_email", "email", "Email", "ACTIVE", email),
            auth("okta_password", "password", "Password", "ACTIVE"),
            auth("okta_verify", "app", "Okta Verify", "ACTIVE"),
            auth("phone_number", "phone", "Phone", phone),
            auth("webauthn", "security_key", "Passkey", "ACTIVE"),
            auth("security_question", "security_question", "Security Question", "INACTIVE", "recovery"),
        ],
        "authenticatorMethods": [
            [m("email", "ACTIVE")], [m("password", "ACTIVE")],
            [m(x.split(":")[0], x.split(":")[1]) for x in verify],
            [m("sms", phone), m("voice", "INACTIVE")], [m("webauthn", "ACTIVE")], [m("security_question", "INACTIVE")],
        ],
    }


class AuthenticatorPostureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = load()

    def run_(self, body):
        res = self.t.transform(body)
        return res, res["transformedResponse"], res["additionalInfo"]["evaluation"]["failReasons"]

    def test_verify_totp_fails_with_totp_reason_not_sms(self):
        res, out, fails = self.run_(posture())
        self.assertIs(out[KEY], False)
        self.assertEqual(out["activePhishableFactors"], ["Okta Verify one-time code"])
        self.assertTrue(fails[0].startswith("Okta Verify one-time code is enabled"))
        self.assertNotIn("sms", json.dumps(out).lower())
        self.assertEqual(res["additionalInfo"]["dataCollection"]["status"], "success")

    def test_wrapped_and_unredacted_key_read_the_same(self):
        body = posture()
        for a in body["authenticators"]:
            a["key"] = "<redacted>"
        for wrapped in ({"apiResponse": posture()}, {"data": posture(), "validation": {"status": "unknown"}},
                        json.dumps(posture()), body):
            with self.subTest(body=str(wrapped)[:40]):
                self.assertEqual(self.t.transform(wrapped)["transformedResponse"]["activePhishableFactors"],
                                 ["Okta Verify one-time code"])

    def test_passkey_plus_fastpass_only_is_not_evaluated(self):
        res, out, fails = self.run_(posture(verify=("push:INACTIVE", "totp:INACTIVE", "signed_nonce:ACTIVE")))
        self.assertIsNone(out[KEY])
        self.assertIn("FastPass", fails[0])

    def test_passkey_only_passes(self):
        res, out, fails = self.run_(posture(verify=("push:INACTIVE", "totp:INACTIVE", "signed_nonce:INACTIVE")))
        self.assertIs(out[KEY], True)
        self.assertEqual(out["activePhishResistantFactors"], ["Passkey"])

    def test_email_recovery_only_is_not_counted_but_sign_in_fails(self):
        quiet = ("push:INACTIVE", "totp:INACTIVE", "signed_nonce:INACTIVE")
        self.assertIs(self.run_(posture(verify=quiet, email="recovery"))[1][KEY], True)
        for allowed in ("any", "authentication"):
            with self.subTest(allowed=allowed):
                res, out, fails = self.run_(posture(verify=quiet, email=allowed))
                self.assertIs(out[KEY], False)
                self.assertTrue(fails[0].startswith("Email sign-in is enabled"))

    def test_phone_push_and_otp_are_phishable(self):
        quiet = ("push:INACTIVE", "totp:INACTIVE", "signed_nonce:INACTIVE")
        self.assertEqual(self.run_(posture(verify=quiet, phone="ACTIVE"))[1]["activePhishableFactors"],
                         ["Phone (SMS or voice)"])
        self.assertEqual(self.run_(posture(verify=("push:ACTIVE",)))[1]["activePhishableFactors"], ["Okta Verify push"])
        for key, name in (("google_otp", "Google Authenticator"), ("yubikey_token", "YubiKey"), ("x", "Duo Security")):
            with self.subTest(name=name):
                body = posture(verify=quiet)
                body["authenticators"].append(auth(key, "app", name, "ACTIVE"))
                body["authenticatorMethods"].append([])
                self.assertEqual(self.run_(body)[1]["activePhishableFactors"], [name])

    def test_errors_and_empty_are_not_evaluated(self):
        unreadable = posture()
        unreadable["authenticatorMethods"][2] = {"apiResponse": {"errorCode": "E0000006", "errorSummary": "forbidden"}}
        short = posture()
        short["authenticatorMethods"] = short["authenticatorMethods"][:2]
        odd = posture(verify=("totp:INACTIVE",))
        odd["authenticators"].append(auth("custom_thing", "other", "Something new", "ACTIVE"))
        odd["authenticatorMethods"].append([])
        for body in ({"authenticators": []}, {"authenticators": None}, {"authenticators": {"errorCode": "E0000006"}},
                     {"apiResponse": {"authenticators": [], "authenticatorMethods": []}}, unreadable, short, odd,
                     {"authenticators": [auth("okta_verify", "app", "Okta Verify", "ACTIVE")]}):
            with self.subTest(body=str(body)[:60]):
                res = self.t.transform(body)
                self.assertIsNone(res["transformedResponse"][KEY])
                self.assertEqual(res["additionalInfo"]["dataCollection"]["status"], "error")

    def test_classic_fallback_is_unchanged(self):
        res = self.t.transform(REAL)
        self.assertIs(res["transformedResponse"][KEY], False)
        self.assertEqual(res["additionalInfo"]["evaluation"]["failReasons"],
                         ["No phishing-resistant factor (FIDO2/WebAuthn, FIDO U2F, Okta FastPass, smart card) is ACTIVE; "
                          "active factors: token:hardware/YUBICO, token:software:totp/OKTA, sms/OKTA, question/OKTA, "
                          "push/OKTA."])
        self.assertNotIn("source", res["additionalInfo"]["transformation"]["inputSummary"])


try:
    import RestrictedPython  # noqa: F401

    class PhishResistantOnlySandboxTests(PhishResistantOnlyTests):
        @classmethod
        def setUpClass(cls):
            cls.t = SandboxModule()

    class AuthenticatorPostureSandboxTests(AuthenticatorPostureTests):
        @classmethod
        def setUpClass(cls):
            cls.t = SandboxModule()
except ImportError:  # CI installs RestrictedPython from requirements-test.txt
    pass


if __name__ == "__main__":
    unittest.main()
