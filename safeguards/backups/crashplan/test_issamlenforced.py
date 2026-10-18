import importlib.util
import unittest
from pathlib import Path


TRANSFORMATION_PATH = Path(__file__).with_name("isSAMLEnforced.py")


def load_transformation():
    spec = importlib.util.spec_from_file_location("crashplan_issamlenforced", TRANSFORMATION_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def value(out):
    return out["transformedResponse"]["isSAMLEnforced"]


class CrashPlanIsSAMLEnforcedTest(unittest.TestCase):
    """Input shape: the integration's getSecuritySettings returns the org settingsSummary
    (GET /api/v1/Org/{orgId}?incSettings=true) under "securitySettings"."""

    def setUp(self):
        self.t = load_transformation().transform

    def test_org_with_an_sso_identity_provider_is_enforced(self):
        out = self.t({"securitySettings": {"ssoIdentityProviderUids": ["idp-1"], "securityKeyType": "AccountPassword"}})
        self.assertIs(value(out), True)
        self.assertEqual(out["transformedResponse"]["ssoIdentityProviderCount"], 1)

    def test_org_with_no_sso_identity_provider_is_not_enforced(self):
        out = self.t({"securitySettings": {"ssoIdentityProviderUids": [], "securityKeyType": "AccountPassword"}})
        self.assertIs(value(out), False)
        self.assertEqual(out["transformedResponse"]["ssoIdentityProviderCount"], 0)

    def test_no_evidence_is_not_evaluated(self):
        for body in ({}, None, [], {"error": {"code": 403}}, {"securitySettings": {"ssoIdentityProviderUids": None}},
                     {"hello": "world"}):
            with self.subTest(body=body):
                self.assertIsNone(value(self.t(body)))


if __name__ == "__main__":
    unittest.main()
