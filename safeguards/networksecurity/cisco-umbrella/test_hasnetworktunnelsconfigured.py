"""hasNetworkTunnelsConfigured: real tunnel data, and Umbrella's "SIG is not enabled" 403.

On an org without Secure Internet Gateway, Umbrella answers the tunnels endpoint with
403 {"error": "SIG is not enabled, ..."}. Integration-Service hands that one refusal
over as data (method opt-in vendorErrorAsResponse), and this transform reports it as
not applicable: a dataCollection error, which Token-Service shows as Unevaluated and
keeps out of the score. It is neither a PASS nor a FAIL.
"""
import importlib.util
import json
import unittest
from pathlib import Path

TRANSFORMATION_PATH = Path(__file__).with_name("hasnetworktunnelsconfigured.py")
KEY = "hasNetworkTunnelsConfigured"

SIG_BODY = {"error": "SIG is not enabled, please check with Cisco Support if needed."}
SIG_MARKED = {"vendorErrorAsResponse": {
    "status": 403, "bodyContains": "SIG is not enabled", "body": SIG_BODY}}

REAL_TUNNELS = [
    {"id": 511, "name": "HQ-ipsec", "siteOriginId": 1, "state": "active"},
    {"id": 512, "name": "Branch-gre", "siteOriginId": 2, "state": "inactive"},
]


def load_transformation():
    spec = importlib.util.spec_from_file_location("umbrella_hasnetworktunnelsconfigured", TRANSFORMATION_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class UmbrellaNetworkTunnelsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = load_transformation()

    def run_transform(self, payload):
        return self.t.transform(payload)

    def collection(self, response):
        return response["additionalInfo"]["dataCollection"]

    # --- real tunnel data behaves as before ------------------------------------

    def test_real_tunnels_pass(self):
        response = self.run_transform(REAL_TUNNELS)
        self.assertIs(response["transformedResponse"][KEY], True)
        self.assertEqual(response["transformedResponse"]["usableTunnels"], 1)
        self.assertEqual(self.collection(response)["status"], "success")

    def test_flip_all_tunnels_down_fails(self):
        down = [dict(t, state="down") for t in REAL_TUNNELS]
        response = self.run_transform(down)
        self.assertIs(response["transformedResponse"][KEY], False)
        self.assertEqual(self.collection(response)["status"], "success")
        self.assertTrue(response["additionalInfo"]["evaluation"]["failReasons"])

    def test_empty_list_is_a_measured_fail(self):
        # SIG present, no tunnels (200 []): a real FAIL, not "does not apply".
        response = self.run_transform([])
        self.assertIs(response["transformedResponse"][KEY], False)
        self.assertEqual(self.collection(response)["status"], "success")
        self.assertTrue(response["additionalInfo"]["evaluation"]["failReasons"])

    def test_none_and_empty_bodies_fail_closed(self):
        for payload in (None, {}, "{}", "null"):
            with self.subTest(payload=payload):
                self.assertIs(self.run_transform(payload)["transformedResponse"][KEY], False)

    def test_auth_error_envelope_fails_closed(self):
        response = self.run_transform({"error": True, "errorType": "authentication",
                                       "statusCode": 401, "message": "Authentication Failed"})
        self.assertIs(response["transformedResponse"][KEY], False)

    # --- SIG not enabled: not applicable ---------------------------------------

    def assert_not_applicable(self, response):
        self.assertIs(response["transformedResponse"][KEY], False)
        collection = self.collection(response)
        self.assertEqual(collection["status"], "error")
        self.assertEqual(len(collection["errors"]), 1)
        self.assertIn("SIG is not enabled", collection["errors"][0])
        self.assertIn("does not apply", collection["errors"][0])
        self.assertEqual(response["additionalInfo"]["transformation"]["inputSummary"], {"sigEnabled": False})
        # Not a FAIL: no fail reason for the requirement to be judged on.
        self.assertEqual(response["additionalInfo"]["evaluation"]["failReasons"], [])

    def test_sig_not_enabled_is_not_applicable(self):
        self.assert_not_applicable(self.run_transform(SIG_MARKED))

    def test_sig_not_enabled_as_json_string(self):
        self.assert_not_applicable(self.run_transform(json.dumps(SIG_MARKED)))

    def test_sig_not_enabled_in_enriched_input(self):
        self.assert_not_applicable(self.run_transform(
            {"data": SIG_MARKED, "validation": {"status": "valid", "errors": [], "warnings": []}}))

    def test_sig_not_enabled_under_api_response_wrapper(self):
        self.assert_not_applicable(self.run_transform({"apiResponse": SIG_MARKED}))

    def test_other_handed_over_error_is_a_data_collection_error_not_sig(self):
        other = {"vendorErrorAsResponse": {"status": 403, "bodyContains": "Forbidden",
                                           "body": {"error": "Forbidden"}}}
        response = self.run_transform(other)
        self.assertIs(response["transformedResponse"][KEY], False)
        self.assertEqual(self.collection(response)["status"], "error")
        self.assertNotIn("does not apply", self.collection(response)["errors"][0])

    def test_sig_text_with_wrong_status_is_not_treated_as_sig(self):
        wrong = {"vendorErrorAsResponse": {"status": 500, "bodyContains": "SIG is not enabled",
                                           "body": SIG_BODY}}
        response = self.run_transform(wrong)
        self.assertIs(response["transformedResponse"][KEY], False)
        self.assertNotIn("does not apply", self.collection(response)["errors"][0])

    def test_bare_error_body_without_marker_is_not_treated_as_sig(self):
        # Only Integration-Service's marked shape counts; a bare body is not tunnel data.
        response = self.run_transform(SIG_BODY)
        self.assertIs(response["transformedResponse"][KEY], False)
        self.assertEqual(response["additionalInfo"]["transformation"]["inputSummary"].get("sigEnabled"), None)


if __name__ == "__main__":
    unittest.main()
