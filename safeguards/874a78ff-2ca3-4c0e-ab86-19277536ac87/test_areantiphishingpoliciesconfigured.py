import importlib.util
import unittest
from pathlib import Path

PATH = Path(__file__).with_name("areantiphishingpoliciesconfigured.py")
KEY = "areAntiPhishingPoliciesConfigured"

# Error objects from the Exchange Lambda path (synthetic). None is evidence about the control.
COLLECTOR_ERRORS = {
    "integration_service_502": {"result": {"apiResponse": {
        "integrationName": "Example", "errorMessage": "An error occurred while processing your request.",
        "vendorStatus": 502, "vendorErrorType": "vendor_error",
        "vendorError": '{"Type": "User", "message": "example"}'}}},
    "lambda_service_body": {"Type": "User", "message": "example"},
    "handler_error": {"error": "Internal error"},
    "script_crashed": {"Success": False, "Output": "", "Error": "example stderr"},
    "script_reported_failure": {"Success": True, "Output": {"success": False, "organizationDomain": None}},
}


def load():
    spec = importlib.util.spec_from_file_location("areantiphishingpoliciesconfigured", PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def policy(enabled=True):
    return {
        "Name": "Example", "Enabled": enabled, "EnableMailboxIntelligence": True,
        "EnableMailboxIntelligenceProtection": True, "TargetedDomainProtectionAction": "Quarantine",
        "EnableSpoofIntelligence": True, "EnableUnauthenticatedSender": True,
        "AuthenticationFailAction": "Quarantine", "EnableFirstContactSafetyTips": True,
        "EnableSimilarUsersSafetyTips": True, "EnableSimilarDomainsSafetyTips": True,
        "EnableUnusualCharactersSafetyTips": True, "EnableViaTag": True, "PhishThresholdLevel": 2,
    }


class AntiPhishingPoliciesConfiguredTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = load()

    def test_collector_error_objects_are_not_evaluated(self):
        for name, payload in COLLECTOR_ERRORS.items():
            with self.subTest(name=name):
                r = self.t.transform(payload)
                self.assertIsNone(r["transformedResponse"][KEY])
                self.assertEqual(r["additionalInfo"]["dataCollection"]["status"], "error")
                self.assertTrue(r["additionalInfo"]["dataCollection"]["errors"])
                self.assertTrue(r["additionalInfo"]["evaluation"]["recommendations"])
                self.assertNotIn("example", str(r["additionalInfo"]))

    def test_failed_validation_is_not_evaluated(self):
        r = self.t.transform({"data": {"vendorStatus": 502}, "validation": {"status": "failed", "errors": ["x"], "warnings": []}})
        self.assertIsNone(r["transformedResponse"][KEY])
        self.assertEqual(r["additionalInfo"]["dataCollection"]["status"], "error")

    def test_missing_or_non_list_is_not_evaluated(self):
        for payload in ({"Output": {}}, {"Output": {"policies": None}}, {"Output": {"policies": "x"}}):
            with self.subTest(payload=payload):
                self.assertIsNone(self.t.transform(payload)["transformedResponse"][KEY])

    def test_real_shape_passes(self):
        r = self.t.transform({"Output": {"policies": [policy()]}})
        self.assertIs(r["transformedResponse"][KEY], True)
        self.assertEqual(r["additionalInfo"]["dataCollection"]["status"], "success")

    def test_empty_list_is_a_stated_negative(self):
        r = self.t.transform({"Output": {"policies": []}})
        self.assertIs(r["transformedResponse"][KEY], False)
        self.assertEqual(r["additionalInfo"]["dataCollection"]["status"], "success")

    def test_negative_shape_fails(self):
        r = self.t.transform({"Output": {"policies": [policy(enabled=False)]}})
        self.assertIs(r["transformedResponse"][KEY], False)
        self.assertEqual(r["additionalInfo"]["dataCollection"]["status"], "success")


    def test_non_dict_policies_are_not_graded(self):
        for policies in (["x"], [None]):
            r = self.t.transform({"Output": {"policies": policies}}) if hasattr(self, "t") else None
            self.assertIsNone(r["transformedResponse"][KEY])


if __name__ == "__main__":
    unittest.main()
