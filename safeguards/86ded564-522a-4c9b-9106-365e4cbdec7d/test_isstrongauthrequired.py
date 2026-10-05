"""isStrongAuthRequired must not read an Okta org factor catalogue as a policy list.

REAL mirrors an internal test tenant read of 2026-10-05 06:32 UTC, archived as the
`isAdminMFAPhishingResistant` api_response (factorType/provider/status
only, nothing else kept). GET /api/v1/org/factors returned 17 rows with exactly two ACTIVE:
sms/OKTA and token:software:totp/OKTA.

Against that body the old logic answered True -- "Strong authentication is required with 2
active policies" -- where the two "policies" were SMS and TOTP. It must now answer None.
"""
import importlib.util
import json
import unittest
from pathlib import Path

PATH = Path(__file__).with_name("isstrongauthrequired.py")
KEY = "isStrongAuthRequired"

ROOT = PATH.resolve().parents[2]


def load():
    spec = importlib.util.spec_from_file_location("isstrongauthrequired", PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SandboxModule:
    """The same file compiled as Token-Service runs it (RestrictedPython replica in tools/)."""

    def __init__(self):
        spec = importlib.util.spec_from_file_location(
            "restricted_sandbox_isstrongauthrequired", ROOT / "tools" / "restricted_sandbox.py"
        )
        sandbox = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(sandbox)
        self.transform = sandbox.load(PATH.read_text(), "<transformation>")["transform"]


def f(kind, provider, status):
    return {"factorType": kind, "provider": provider, "status": status}


def p(name, status):
    return {"id": name, "name": name, "type": "ACCESS_POLICY", "status": status}


REAL = [
    f("token", "RSA", "NOT_SETUP"),
    f("token:hardware", "YUBICO", "NOT_SETUP"),
    f("token", "SYMANTEC", "NOT_SETUP"),
    f("token:hotp", "CUSTOM", "NOT_SETUP"),
    f("web", "DUO", "NOT_SETUP"),
    f("token", "RSA", "NOT_SETUP"),
    f("smart_card", "SMART_CARD", "INACTIVE"),
    f("call", "OKTA", "INACTIVE"),
    f("push", "OKTA", "INACTIVE"),
    f("email", "OKTA", "INACTIVE"),
    f("question", "OKTA", "INACTIVE"),
    f("signed_nonce", "OKTA", "INACTIVE"),
    f("token:software:totp", "GOOGLE", "INACTIVE"),
    f("webauthn", "FIDO", "INACTIVE"),
    f("u2f", "FIDO", "INACTIVE"),
    f("sms", "OKTA", "ACTIVE"),
    f("token:software:totp", "OKTA", "ACTIVE"),
]


def verdict(response):
    return response["transformedResponse"][KEY]


def reasons(response):
    ev = response["additionalInfo"]["evaluation"]
    return " ".join(ev["passReasons"] + ev["failReasons"])


def summary(response):
    return response["additionalInfo"]["transformation"]["inputSummary"]


class FactorCatalogueIsNotAPolicyList(unittest.TestCase):
    def setUp(self):
        self.transform = load().transform

    def test_real_tenant_body_is_not_evaluated(self):
        """The regression: 17 org factors, 2 ACTIVE, previously read as 2 active policies."""
        self.assertIsNone(verdict(self.transform(REAL)))

    def test_real_tenant_body_is_not_true(self):
        """Stated separately: the old answer was True and that must never come back."""
        self.assertNotEqual(verdict(self.transform(REAL)), True)

    def test_reason_names_the_endpoint_and_the_shape(self):
        text = reasons(self.transform(REAL))
        self.assertIn("/api/v1/org/factors", text)
        self.assertIn("factorType", text)

    def test_summary_reports_the_active_factors_it_refused_to_count(self):
        got = summary(self.transform(REAL))
        self.assertEqual(got["shape"], "factor-catalogue")
        self.assertEqual(got["factorEntries"], 17)
        self.assertEqual(got["activeFactors"], ["sms/OKTA", "token:software:totp/OKTA"])

    def test_wrapped_in_api_response(self):
        self.assertIsNone(verdict(self.transform({"api_response": REAL})))

    def test_a_json_string_body(self):
        self.assertIsNone(verdict(self.transform(json.dumps(REAL))))

    def test_all_factors_inactive_is_still_not_evaluated(self):
        """Not a finding either -- the catalogue cannot answer the question at all."""
        body = [f("sms", "OKTA", "INACTIVE"), f("webauthn", "FIDO", "INACTIVE")]
        self.assertIsNone(verdict(self.transform(body)))

    def test_a_single_factor_row_is_enough_to_refuse(self):
        self.assertIsNone(verdict(self.transform([f("sms", "OKTA", "ACTIVE")])))


class GenuinePolicyListStillWorks(unittest.TestCase):
    """This file is shared. A vendor that really sends policies must be unaffected."""

    def setUp(self):
        self.transform = load().transform

    def test_active_policy_passes(self):
        self.assertTrue(verdict(self.transform([p("Require MFA", "ACTIVE")])))

    def test_lowercase_status_passes(self):
        self.assertTrue(verdict(self.transform([p("Require MFA", "active")])))

    def test_counts_only_the_active_ones(self):
        body = [p("a", "ACTIVE"), p("b", "INACTIVE"), p("c", "ACTIVE")]
        response = self.transform(body)
        self.assertTrue(verdict(response))
        self.assertEqual(summary(response)["activePolicies"], 2)
        self.assertEqual(summary(response)["shape"], "policies")

    def test_no_active_policy_fails(self):
        """The reachable False. Without this the check could not report anything."""
        body = [p("a", "INACTIVE"), p("b", "INACTIVE")]
        self.assertFalse(verdict(self.transform(body)))

    def test_fail_reason_is_unchanged(self):
        body = [p("a", "INACTIVE")]
        self.assertIn("No strong authentication policies configured",
                      reasons(self.transform(body)))


class UnreadableBodiesAreNotFindings(unittest.TestCase):
    def setUp(self):
        self.transform = load().transform

    def test_empty_dict(self):
        self.assertIsNone(verdict(self.transform({})))

    def test_none(self):
        self.assertIsNone(verdict(self.transform(None)))

    def test_empty_list(self):
        self.assertIsNone(verdict(self.transform([])))

    def test_list_of_non_objects(self):
        self.assertIsNone(verdict(self.transform(["sms", "totp"])))

    def test_okta_error_envelope(self):
        body = {"errorCode": "E0000006",
                "errorSummary": "You do not have permission to perform the requested action"}
        self.assertIsNone(verdict(self.transform(body)))

    def test_error_envelope_reports_shape(self):
        body = {"errorCode": "E0000006", "errorSummary": "nope"}
        self.assertEqual(summary(self.transform(body))["shape"], "error")

    def test_a_string_that_is_not_json(self):
        self.assertIsNone(verdict(self.transform("not json at all")))

    def test_bare_string_body(self):
        self.assertIsNone(verdict(self.transform("")))


class RunsUnderTheSandbox(unittest.TestCase):
    """RestrictedPython rejects leading-underscore names and augmented subscript assignment."""

    def setUp(self):
        self.transform = SandboxModule().transform

    def test_real_tenant_body(self):
        self.assertIsNone(verdict(self.transform(REAL)))

    def test_policy_list_passes(self):
        self.assertTrue(verdict(self.transform([p("Require MFA", "ACTIVE")])))

    def test_policy_list_fails(self):
        self.assertFalse(verdict(self.transform([p("a", "INACTIVE")])))

    def test_empty_dict(self):
        self.assertIsNone(verdict(self.transform({})))


if __name__ == "__main__":
    unittest.main()
