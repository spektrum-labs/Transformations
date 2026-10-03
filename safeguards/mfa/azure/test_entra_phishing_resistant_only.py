"""isPhishingResistantOnlyEnabled (entra_phishing_resistant_only.py) on GET /v1.0/policies/authenticationMethodsPolicy.

REAL mirrors the shape of a customer tenant read stored 2026-10-03 02:23 ET (Azure AD One-Click,
getEstateMFAStatus): Microsoft Authenticator (all users) and Software OATH (one group) enabled, every other method
disabled, policyMigrationState migrationComplete. Group ids are replaced. It passed CSP-001 through
authTypesAllowed; here it must read False. Each case runs as plain Python and in the Token-Service sandbox replica.
"""
import copy
import importlib.util
import json
import unittest
from pathlib import Path

PATH = Path(__file__).with_name("entra_phishing_resistant_only.py")
ROOT = PATH.resolve().parents[3]
KEY = "isPhishingResistantOnlyEnabled"
GROUP = "00000000-0000-0000-0000-0000000000aa"


def target(gid="all_users", **extra):
    t = {"targetType": "group", "id": gid, "isRegistrationRequired": False}
    t.update(extra)
    return t


def cfg(odata, mid, state, targets=None, **extra):
    c = {"@odata.type": "#microsoft.graph." + odata, "id": mid, "state": state, "excludeTargets": [],
         "includeTargets": [target()] if targets is None else targets}
    c.update(extra)
    return c


def policy(*overrides, migration="migrationComplete"):
    configs = {
        "Fido2": cfg("fido2AuthenticationMethodConfiguration", "Fido2", "disabled", isAttestationEnforced=False),
        "MicrosoftAuthenticator": cfg("microsoftAuthenticatorAuthenticationMethodConfiguration",
                                      "MicrosoftAuthenticator", "enabled",
                                      [target(authenticationMode="any")], isSoftwareOathEnabled=True),
        "Sms": cfg("smsAuthenticationMethodConfiguration", "Sms", "disabled"),
        "TemporaryAccessPass": cfg("temporaryAccessPassAuthenticationMethodConfiguration", "TemporaryAccessPass",
                                   "disabled", defaultLifetimeInMinutes=60, maximumLifetimeInMinutes=480),
        "SoftwareOath": cfg("softwareOathAuthenticationMethodConfiguration", "SoftwareOath", "enabled",
                            [target(GROUP)]),
        "Voice": cfg("voiceAuthenticationMethodConfiguration", "Voice", "disabled"),
        "Email": cfg("emailAuthenticationMethodConfiguration", "Email", "disabled", [],
                     allowExternalIdToUseEmailOtp="default"),
        "X509Certificate": cfg("x509CertificateAuthenticationMethodConfiguration", "X509Certificate", "disabled"),
    }
    for mid, changes in overrides:
        configs[mid] = dict(configs[mid], **changes)
    return {
        "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#authenticationMethodsPolicy",
        "id": "authenticationMethodsPolicy", "displayName": "Authentication Methods Policy",
        "policyVersion": "1.5", "policyMigrationState": migration,
        "registrationEnforcement": {"authenticationMethodsRegistrationCampaign": {"state": "default"}},
        "authenticationMethodConfigurations": list(configs.values()),
    }


REAL = policy()
OFF = [("MicrosoftAuthenticator", {"state": "disabled"}), ("SoftwareOath", {"state": "disabled"})]
FIDO_ONLY = OFF + [("Fido2", {"state": "enabled"})]
DUO = {"@odata.type": "#microsoft.graph.externalAuthenticationMethodConfiguration", "id": "11111111-2222-3333-4444-555555555555",
       "displayName": "Cisco Duo", "state": "enabled", "appId": "x", "includeTargets": [target()], "excludeTargets": []}


def load():
    spec = importlib.util.spec_from_file_location("entra_phishing_resistant_only", PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SandboxModule:
    def __init__(self):
        spec = importlib.util.spec_from_file_location("restricted_sandbox_entra_pro", ROOT / "tools" / "restricted_sandbox.py")
        sandbox = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(sandbox)
        self.transform = sandbox.load(PATH.read_text(), "<transformation>")["transform"]


class EntraPhishResistantOnlyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = load()

    def run_t(self, body):
        return self.t.transform(copy.deepcopy(body))

    def value(self, body):
        return self.run_t(body)["transformedResponse"][KEY]

    def assert_unevaluated(self, body):
        res = self.run_t(body)
        self.assertIsNone(res["transformedResponse"][KEY])
        self.assertEqual(res["additionalInfo"]["dataCollection"]["status"], "error")
        return res

    def test_real_authenticator_and_oath_fails(self):
        res = self.run_t(REAL)
        self.assertIs(res["transformedResponse"][KEY], False)
        self.assertEqual(res["transformedResponse"]["enabledPhishableMethods"], ["MicrosoftAuthenticator", "SoftwareOath"])
        self.assertEqual(res["additionalInfo"]["dataCollection"]["status"], "success")

    def test_one_click_and_azure_ad_envelopes_read_the_same(self):
        for body in ({"apiResponse": REAL}, {"response": {"result": REAL}}, json.dumps(REAL),
                     json.dumps(REAL).encode("utf-8"), {"data": REAL, "validation": {"status": "unknown"}}):
            with self.subTest(body=str(body)[:30]):
                self.assertIs(self.value(body), False)

    def test_fido2_only_passes(self):
        res = self.run_t(policy(*FIDO_ONLY))
        self.assertIs(res["transformedResponse"][KEY], True)
        self.assertEqual(res["transformedResponse"]["enabledPhishableMethods"], [])

    def test_certificate_only_passes(self):
        self.assertIs(self.value(policy(*(OFF + [("X509Certificate", {"state": "enabled"})]))), True)

    def test_fido2_plus_any_phishable_fails(self):
        # isStrongAuthRequired passes every one of these; this key must not.
        for mid in ("MicrosoftAuthenticator", "Sms", "Voice", "SoftwareOath"):
            with self.subTest(mid=mid):
                self.assertIs(self.value(policy(*(FIDO_ONLY + [(mid, {"state": "enabled"})]))), False)

    def test_unknown_method_counts_as_phishable(self):
        body = policy(*FIDO_ONLY)
        body["authenticationMethodConfigurations"].append(
            cfg("hardwareOathAuthenticationMethodConfiguration", "HardwareOath", "enabled"))
        self.assertIs(self.value(body), False)
        body["authenticationMethodConfigurations"][-1] = cfg("qrCodePinAuthenticationMethodConfiguration", "QRCodePin", "enabled")
        self.assertIs(self.value(body), False)

    def test_guest_only_email_otp_fails(self):
        # J.J. 3 Oct 2026 00:55 ET: guest-only email OTP FAILS.
        res = self.run_t(policy(*(FIDO_ONLY + [("Email", {"state": "enabled"})])))
        self.assertIs(res["transformedResponse"][KEY], False)
        self.assertIs(res["transformedResponse"]["guestOnlyEmailOtp"], True)

    def test_bounded_tap_is_allowed_with_a_finding(self):
        res = self.run_t(policy(*(FIDO_ONLY + [("TemporaryAccessPass", {"state": "enabled"})])))
        self.assertIs(res["transformedResponse"][KEY], True)
        self.assertTrue(res["additionalInfo"]["evaluation"]["additionalFindings"])

    def test_unbounded_tap_fails(self):
        tap = {"state": "enabled", "maximumLifetimeInMinutes": None}
        self.assertIs(self.value(policy(*(FIDO_ONLY + [("TemporaryAccessPass", tap)]))), False)

    def test_untargeted_non_email_method_is_a_finding(self):
        res = self.run_t(policy(*(FIDO_ONLY + [("Sms", {"state": "enabled", "includeTargets": []})])))
        self.assertIs(res["transformedResponse"][KEY], True)
        self.assertIn("Sms", res["additionalInfo"]["evaluation"]["additionalFindings"][0])

    def test_external_method_is_not_evaluated(self):
        body = policy(*FIDO_ONLY)
        body["authenticationMethodConfigurations"].append(DUO)
        self.assertIn("Cisco Duo", self.assert_unevaluated(body)["additionalInfo"]["dataCollection"]["errors"][0])

    def test_external_plus_phishable_fails(self):
        body = policy()
        body["authenticationMethodConfigurations"].append(DUO)
        self.assertIs(self.value(body), False)

    def test_legacy_migration_state_is_not_evaluated(self):
        for state in ("preMigration", "migrationInProgress"):
            with self.subTest(state=state):
                self.assert_unevaluated(policy(*FIDO_ONLY, migration=state))
                self.assertIs(self.value(policy(migration=state)), False)

    def test_no_member_method_is_not_evaluated(self):
        self.assert_unevaluated(policy(*OFF))
        self.assert_unevaluated(policy(*(OFF + [("TemporaryAccessPass", {"state": "enabled"})])))

    def test_partial_or_no_evidence_bodies_are_not_evaluated(self):
        partial = policy(*FIDO_ONLY)
        partial["authenticationMethodConfigurations"][2].pop("state")
        no_id = policy(*FIDO_ONLY)
        no_id["authenticationMethodConfigurations"][1]["id"] = ""
        for body in (None, {}, [], "", "null", "not json", b"", 0, partial, no_id,
                     {"error": {"code": "Authorization_RequestDenied", "message": "Insufficient privileges"}},
                     {"authenticationMethodConfigurations": []}, {"authenticationMethodConfigurations": None},
                     {"authenticationMethodConfigurations": ["Fido2"]}, {"value": []}, {"apiResponse": {}},
                     {"data": REAL, "validation": {"status": "failed", "errors": ["x"]}}):
            with self.subTest(body=str(body)[:40]):
                self.assert_unevaluated(body)


try:
    import RestrictedPython  # noqa: F401

    class EntraPhishResistantOnlySandboxTests(EntraPhishResistantOnlyTests):
        @classmethod
        def setUpClass(cls):
            cls.t = SandboxModule()
except ImportError:  # CI installs RestrictedPython from requirements-test.txt
    pass


if __name__ == "__main__":
    unittest.main()
