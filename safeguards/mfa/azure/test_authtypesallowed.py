import importlib.util
import unittest
from pathlib import Path


TRANSFORMATION_PATH = Path(__file__).with_name("authtypesallowed.py")
# Azure AD One-Click (cde89168) runs the copy in the Azure AD safeguard folder; the two files
# must give the same verdicts, so every test below runs against both.
ONECLICK_PATH = Path(__file__).resolve().parents[2] / "d9b6f27a-2e67-4b55-a09e-0784c5de9abd" / "auth_types_allowed.py"


def load_transformation(path=TRANSFORMATION_PATH):
    spec = importlib.util.spec_from_file_location("azure_authtypesallowed_" + path.parent.name.replace("-", "_"), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def policy(enabled):
    """Graph GET /v1.0/policies/authenticationMethodsPolicy: a single object, not a list."""
    ids = ["Email", "Fido2", "MicrosoftAuthenticator", "QRCodePin", "Sms", "SoftwareOath",
           "TemporaryAccessPass", "VerifiableCredentials", "Voice", "X509Certificate"]
    return {
        "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#policies/authenticationMethodsPolicy/$entity",
        "id": "authenticationMethodsPolicy",
        "authenticationMethodConfigurations": [
            {"id": i, "state": "enabled" if i in enabled else "disabled"} for i in ids
        ],
    }


class AzureAuthTypesAllowedTests(unittest.TestCase):
    PATH = TRANSFORMATION_PATH

    @classmethod
    def setUpClass(cls):
        cls.t = load_transformation(cls.PATH)

    def verdict(self, body):
        out = self.t.transform(body)
        return out["transformedResponse"]["authTypesAllowed"], out["additionalInfo"]["dataCollection"]["status"]

    def test_policy_object_with_weak_method_is_evaluated_false(self):
        self.assertEqual(self.verdict(policy({"Fido2", "MicrosoftAuthenticator", "Email"})), (False, "success"))

    def test_policy_object_with_only_strong_methods_is_evaluated_true(self):
        self.assertEqual(self.verdict(policy({"Fido2", "MicrosoftAuthenticator", "SoftwareOath"})), (True, "success"))

    def test_no_evidence_fails_closed(self):
        for body in ({}, [], None,
                     {"error": {"code": "InvalidAuthenticationToken"}, "status_code": 401},
                     {"error": {"code": "Authorization_RequestDenied"}, "status_code": 403}):
            with self.subTest(body=body):
                self.assertEqual(self.verdict(body), (False, "error"))

    def cfg(self, **kw):
        base = {"state": "enabled"}
        base.update(kw)
        return base

    def body(self, configs, migration="migrationComplete"):
        return {"policyMigrationState": migration, "authenticationMethodConfigurations": configs}

    def info(self, body):
        return self.t.transform(body)["additionalInfo"]

    # Josh, 5 Oct 2026, superseding J.J.'s 3 Oct rule: a method enabled with an EMPTY
    # includeTargets list targets nobody, so it is not counted -- neither weak nor strong.
    # Both shapes occur in real tenants (Email with empty targets, and Email targeted at
    # all_users or a group), so member-targeted email OTP still occurs and still fails
    # (test_member_targeted_email_otp_fails).
    def test_zero_target_email_otp_is_not_counted(self):
        configs = [self.cfg(id="MicrosoftAuthenticator"),
                   self.cfg(id="Email", allowExternalIdToUseEmailOtp="default", includeTargets=[])]
        self.assertEqual(self.verdict(self.body(configs)), (True, "success"))
        info = self.info(self.body(configs))
        self.assertEqual(info["evaluation"]["failReasons"], [])
        self.assertEqual(info["transformation"]["inputSummary"]["zeroTargetMethodsIgnored"], ["Email"])

    def test_zero_target_email_otp_as_only_method_is_not_evaluated(self):
        # Removing the zero-target method leaves nothing enabled, which is the existing
        # "no member method" rule: not evaluated. Tenants in this position are typically
        # migrationInProgress, where legacy per-user MFA governs sign-in.
        configs = [self.cfg(id="Email", includeTargets=[]), {"id": "Sms", "state": "disabled"}]
        for migration in ("preMigration", "migrationInProgress", "migrationComplete"):
            with self.subTest(migration=migration):
                self.assertEqual(self.verdict(self.body(configs, migration)), (False, "error"))
                errors = " ".join(self.info(self.body(configs, migration))["dataCollection"]["errors"])
                self.assertIn("No member authentication method is enabled", errors)

    def test_guest_email_otp_is_an_additional_finding_only_when_an_admin_chose_it(self):
        chosen = [self.cfg(id="MicrosoftAuthenticator"),
                  self.cfg(id="Email", allowExternalIdToUseEmailOtp="enabled", includeTargets=[])]
        info = self.info(self.body(chosen))
        self.assertEqual(self.verdict(self.body(chosen)), (True, "success"))
        self.assertTrue(any("B2B guest" in f for f in info["evaluation"]["additionalFindings"]))

    def test_guest_email_otp_on_microsofts_default_raises_nothing(self):
        # "default" is Microsoft's tenant default, not an admin choice.
        default = [self.cfg(id="MicrosoftAuthenticator"),
                   self.cfg(id="Email", allowExternalIdToUseEmailOtp="default", includeTargets=[])]
        findings = self.info(self.body(default))["evaluation"]["additionalFindings"]
        self.assertFalse(any("guest" in f.lower() for f in findings))

    def test_a_missing_include_targets_key_is_unknown_not_empty(self):
        # Only a PRESENT and EMPTY list targets nobody. No key at all is still classified.
        configs = [self.cfg(id="MicrosoftAuthenticator"), self.cfg(id="Email")]
        self.assertEqual(self.verdict(self.body(configs)), (False, "success"))

    def test_zero_target_applies_to_every_method_not_only_email(self):
        weak_nobody = [self.cfg(id="MicrosoftAuthenticator"), self.cfg(id="Sms", includeTargets=[])]
        self.assertEqual(self.verdict(self.body(weak_nobody)), (True, "success"))
        # ...and a strong method nobody can use is not evidence of strong auth either.
        strong_nobody = [self.cfg(id="Fido2", includeTargets=[])]
        self.assertEqual(self.verdict(self.body(strong_nobody)), (False, "error"))

    def test_recommendation_no_longer_tells_members_to_fix_a_guest_default(self):
        configs = [self.cfg(id="Fido2"), self.cfg(id="Sms", includeTargets=[{"targetType": "group", "id": "g"}])]
        recs = " ".join(self.info(self.body(configs))["evaluation"]["recommendations"])
        self.assertNotIn("guests", recs)

    def test_member_targeted_email_otp_fails(self):
        configs = [self.cfg(id="MicrosoftAuthenticator"),
                   self.cfg(id="Email", includeTargets=[{"targetType": "group", "id": "all_users"}])]
        self.assertEqual(self.verdict(self.body(configs)), (False, "success"))

    def test_sms_or_voice_still_fails(self):
        for weak in ("Sms", "Voice"):
            with self.subTest(weak=weak):
                configs = [self.cfg(id="Fido2"), self.cfg(id=weak, includeTargets=[{"targetType": "group", "id": "g1"}])]
                self.assertEqual(self.verdict(self.body(configs)), (False, "success"))

    def test_bounded_temporary_access_pass_does_not_fail(self):
        for strong in (["Fido2", "MicrosoftAuthenticator"], ["MicrosoftAuthenticator"], ["SoftwareOath"]):
            with self.subTest(strong=strong):
                configs = [self.cfg(id=i) for i in strong]
                configs.append(self.cfg(id="TemporaryAccessPass", maximumLifetimeInMinutes="480"))
                self.assertEqual(self.verdict(self.body(configs)), (True, "success"))

    def test_bounded_temporary_access_pass_with_zero_target_email_passes(self):
        # A common "case B" shape: strong methods for everyone, a bounded TAP,
        # and Email enabled with empty targets. Neither the TAP nor the Email is counted.
        configs = [self.cfg(id="Fido2"), self.cfg(id="MicrosoftAuthenticator"),
                   self.cfg(id="TemporaryAccessPass", maximumLifetimeInMinutes=480),
                   self.cfg(id="Email", includeTargets=[])]
        self.assertEqual(self.verdict(self.body(configs)), (True, "success"))
        info = self.info(self.body(configs))
        self.assertEqual(info["evaluation"]["failReasons"], [])
        self.assertTrue(any("Temporary Access Pass" in f for f in info["evaluation"]["additionalFindings"]))

    def test_unbounded_temporary_access_pass_fails(self):
        for lifetime in (None, 0, "", "abc"):
            with self.subTest(lifetime=lifetime):
                tap = self.cfg(id="TemporaryAccessPass")
                if lifetime is not None:
                    tap["maximumLifetimeInMinutes"] = lifetime
                self.assertEqual(self.verdict(self.body([self.cfg(id="Fido2"), tap])), (False, "success"))

    def test_x509_and_hardware_oath_are_allowed(self):
        for strong in ("X509Certificate", "HardwareOath"):
            with self.subTest(strong=strong):
                self.assertEqual(self.verdict(self.body([self.cfg(id=strong)])), (True, "success"))

    def test_external_method_alone_is_not_evaluated(self):
        duo = self.cfg(id="bfa47a53", displayName="Cisco Duo",
                       **{"@odata.type": "#microsoft.graph.externalAuthenticationMethodConfiguration"})
        for configs in ([duo], [duo, self.cfg(id="TemporaryAccessPass", maximumLifetimeInMinutes=60)],
                        [duo, self.cfg(id="MicrosoftAuthenticator")]):
            with self.subTest(configs=configs):
                self.assertEqual(self.verdict(self.body(configs)), (False, "error"))

    def test_external_method_with_sms_fails_on_sms(self):
        duo = self.cfg(id="bfa47a53", **{"@odata.type": "#microsoft.graph.externalAuthenticationMethodConfiguration"})
        self.assertEqual(self.verdict(self.body([duo, self.cfg(id="Sms")])), (False, "success"))

    def test_no_member_method_is_not_evaluated(self):
        configs = [{"id": "Sms", "state": "disabled"}, {"id": "Email", "state": "disabled"}]
        for migration in ("preMigration", "migrationInProgress", "migrationComplete"):
            with self.subTest(migration=migration):
                self.assertEqual(self.verdict(self.body(configs, migration)), (False, "error"))
                errors = " ".join(self.info(self.body(configs, migration))["dataCollection"]["errors"])
                self.assertIn("policyMigrationState: " + migration, errors)
        self.assertEqual(self.verdict(self.body(configs, "")), (False, "error"))
        self.assertNotIn("policyMigrationState",
                         " ".join(self.info(self.body(configs, ""))["dataCollection"]["errors"]))

    def test_bounded_tap_alone_is_not_evaluated(self):
        configs = [self.cfg(id="TemporaryAccessPass", maximumLifetimeInMinutes=60)]
        self.assertEqual(self.verdict(self.body(configs)), (False, "error"))


class OneClickAuthTypesAllowedTests(AzureAuthTypesAllowedTests):
    """Same verdicts from the Azure AD safeguard copy that Azure AD One-Click runs."""
    PATH = ONECLICK_PATH


if __name__ == "__main__":
    unittest.main()
