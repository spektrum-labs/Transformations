"""isAdminMFAPhishingResistant for JumpCloud reads GET /api/v2/authn/policies.

THE BUG THIS FIXES. `effect.obligations.mfaFactors` is an array of OBJECTS -- [{"type": "WEBAUTHN"}]
-- but the check compared those dicts against a list of STRINGS:

    any(f in PHISHING_RESISTANT_FACTORS for f in factors)   # f is {"type": "WEBAUTHN"}

`{"type": "WEBAUTHN"} in ["WEBAUTHN", ...]` is always False, so the criterion returned False for
every JumpCloud tenant, including one correctly configured with a WebAuthn-only admin-portal
policy. A fabricated finding.

Compounding it, four of the five values it looked for do not exist in JumpCloud's API. Per their
OpenAPI v2 (schema AuthnPolicyObligations) the type enum is exactly DURT, WEBAUTHN, PUSH, DUO,
TOTP, SMS_OTP. A strict search of the 3 MB spec for FIDO, FIDO2, PIV, SMARTCARD and SMART_CARD
returns nothing.

WEBAUTHN_ONLY is the regression fixture: an admin-portal policy requiring MFA with WebAuthn, which
must now pass and previously could not.
"""
import importlib.util
import json
import unittest
from pathlib import Path

PATH = Path(__file__).with_name("isAdminMFAPhishingResistant.py")
KEY = "isAdminMFAPhishingResistant"

ROOT = PATH.resolve().parents[3]


def load():
    spec = importlib.util.spec_from_file_location("jc_admin_mfa", PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SandboxModule:
    """The same file compiled as Token-Service runs it (RestrictedPython replica in tools/)."""

    def __init__(self):
        spec = importlib.util.spec_from_file_location(
            "restricted_sandbox_jc_admin_mfa", ROOT / "tools" / "restricted_sandbox.py"
        )
        sandbox = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(sandbox)
        self.transform = sandbox.load(PATH.read_text(), "<transformation>")["transform"]


def policy(name, factors, required=True, ptype="admin_portal", disabled=False):
    return {"name": name, "type": ptype, "disabled": disabled,
            "effect": {"obligations": {"mfa": {"required": required}, "mfaFactors": factors}}}


WEBAUTHN_ONLY = [policy("Admin Portal MFA", [{"type": "WEBAUTHN"}])]
PUSH_ONLY = [policy("Admin Portal MFA", [{"type": "PUSH"}])]
MIXED = [policy("Admin Portal MFA", [{"type": "WEBAUTHN"}, {"type": "TOTP"}])]
NO_FACTORS_NAMED = [policy("Admin Portal MFA", None)]


def verdict(response):
    return response["transformedResponse"][KEY]


def reasons(response):
    ev = response["additionalInfo"]["evaluation"]
    return " ".join(ev["passReasons"] + ev["failReasons"])


class TheObjectShapeIsRead(unittest.TestCase):
    def setUp(self):
        self.transform = load().transform

    def test_webauthn_admin_policy_passes(self):
        """The regression: this returned False for every tenant before the fix."""
        self.assertTrue(verdict(self.transform(WEBAUTHN_ONLY)))

    def test_webauthn_alongside_a_phishable_factor_still_passes(self):
        self.assertTrue(verdict(self.transform(MIXED)))

    def test_a_bare_string_array_is_tolerated_too(self):
        self.assertTrue(verdict(self.transform([policy("Admin", ["WEBAUTHN"])])))

    def test_lowercase_is_tolerated(self):
        self.assertTrue(verdict(self.transform([policy("Admin", [{"type": "webauthn"}])])))

    def test_push_only_is_a_real_finding(self):
        self.assertFalse(verdict(self.transform(PUSH_ONLY)))

    def test_every_phishable_factor_fails(self):
        for kind in ("PUSH", "DUO", "TOTP", "SMS_OTP"):
            self.assertFalse(verdict(self.transform([policy("Admin", [{"type": kind}])])), kind)


class FactorsThatJumpCloudDoesNotEmit(unittest.TestCase):
    def setUp(self):
        self.module = load()

    def test_the_allowlist_is_only_what_the_api_can_return(self):
        assert tuple(self.module.PHISHING_RESISTANT_FACTORS) == ("WEBAUTHN",)

    def test_durt_is_counted_neither_way(self):
        """Undocumented in JumpCloud's spec: not claimed as resistant, not held against a tenant."""
        self.assertNotIn("DURT", self.module.PHISHING_RESISTANT_FACTORS)
        self.assertFalse(verdict(self.module.transform([policy("Admin", [{"type": "DURT"}])])))


class UngradablePoliciesAreNotFindings(unittest.TestCase):
    def setUp(self):
        self.transform = load().transform

    def test_mfa_required_without_named_factors_is_unevaluated(self):
        """mfaFactors is optional and "All Enabled" is not exposed by the API, so this is unknown."""
        self.assertIsNone(verdict(self.transform(NO_FACTORS_NAMED)))

    def test_the_reason_says_it_was_not_evaluated(self):
        self.assertIn("not evaluated", reasons(self.transform(NO_FACTORS_NAMED)))

    def test_a_named_resistant_policy_elsewhere_still_passes(self):
        body = NO_FACTORS_NAMED + WEBAUTHN_ONLY
        self.assertTrue(verdict(self.transform(body)))


class ScopeAndShape(unittest.TestCase):
    def setUp(self):
        self.transform = load().transform

    def test_a_non_admin_policy_does_not_satisfy_the_admin_claim(self):
        body = [policy("All users", [{"type": "WEBAUTHN"}], ptype="user_portal")]
        self.assertFalse(verdict(self.transform(body)))

    def test_a_disabled_admin_policy_does_not_satisfy_it(self):
        body = [policy("Admin", [{"type": "WEBAUTHN"}], disabled=True)]
        self.assertFalse(verdict(self.transform(body)))

    def test_mfa_not_required_does_not_satisfy_it(self):
        body = [policy("Admin", [{"type": "WEBAUTHN"}], required=False)]
        self.assertFalse(verdict(self.transform(body)))

    def test_a_bare_array_is_the_documented_envelope(self):
        """GET /authn/policies returns a bare JSON array, with no results wrapper."""
        self.assertTrue(verdict(self.transform(WEBAUTHN_ONLY)))

    def test_a_results_wrapper_is_also_tolerated(self):
        self.assertTrue(verdict(self.transform({"results": WEBAUTHN_ONLY})))

    def test_no_policies_at_all_does_not_pass(self):
        self.assertFalse(verdict(self.transform([])))

    def test_empty_dict_does_not_pass(self):
        self.assertFalse(verdict(self.transform({})))


class RunsUnderTheSandbox(unittest.TestCase):
    def setUp(self):
        self.transform = SandboxModule().transform

    def test_webauthn_passes(self):
        self.assertTrue(verdict(self.transform(WEBAUTHN_ONLY)))

    def test_push_fails(self):
        self.assertFalse(verdict(self.transform(PUSH_ONLY)))

    def test_unnamed_factors_are_unevaluated(self):
        self.assertIsNone(verdict(self.transform(NO_FACTORS_NAMED)))


if __name__ == "__main__":
    unittest.main()
