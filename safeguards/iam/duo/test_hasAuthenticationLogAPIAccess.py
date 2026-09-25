"""hasAuthenticationLogAPIAccess: real Duo v1 authentication logs, and Duo's 403 / 40301 refusal.

When the Admin API application lacks "Grant read log", Duo answers
403 {"code": 40301, "message": "Access forbidden", "stat": "FAIL"}. Integration-Service hands that
one refusal over as data (method opt-in vendorErrorAsResponse), and this transform reports it as a
measured FAIL: the credential has no authentication log access. Any other handed-over error stays a
data-collection error (Unevaluated), never a PASS.
"""
import importlib.util
import json
import unittest
from pathlib import Path

TRANSFORMATION_PATH = Path(__file__).with_name("hasAuthenticationLogAPIAccess.py")
KEY = "hasAuthenticationLogAPIAccess"

FORBIDDEN_BODY = {"code": 40301, "message": "Access forbidden", "stat": "FAIL"}
FORBIDDEN_MARKED = {"vendorErrorAsResponse": {
    "status": 403, "bodyContains": "Access forbidden", "body": FORBIDDEN_BODY}}

RECORDS = [
    {"timestamp": 1790000000, "factor": "duo_push", "result": "success", "username": "u1", "device": "x"},
    {"timestamp": 1790000100, "factor": "passcode", "result": "denied", "username": "u2"},
]


def load_transformation():
    spec = importlib.util.spec_from_file_location("duo_hasAuthenticationLogAPIAccess", TRANSFORMATION_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DuoAuthenticationLogAccessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = load_transformation()

    def run_transform(self, payload):
        return self.t.transform(payload)

    def collection(self, response):
        return response["additionalInfo"]["dataCollection"]

    # --- real log data behaves as before ---------------------------------------

    def test_real_records_pass(self):
        response = self.run_transform({"stat": "OK", "response": RECORDS})
        self.assertIs(response["transformedResponse"][KEY], True)
        self.assertEqual(self.collection(response)["status"], "success")

    def test_flip_record_missing_field_fails(self):
        broken = [dict(RECORDS[0]), {k: v for k, v in RECORDS[1].items() if k != "result"}]
        response = self.run_transform({"stat": "OK", "response": broken})
        self.assertIs(response["transformedResponse"][KEY], False)
        self.assertTrue(response["additionalInfo"]["evaluation"]["failReasons"])

    def test_empty_and_none_fail_closed(self):
        for payload in (None, {}, [], "{}", "null", "not json", {"stat": "OK", "response": []}):
            with self.subTest(payload=payload):
                self.assertIs(self.run_transform(payload)["transformedResponse"][KEY], False)

    # --- 403 / 40301 Access forbidden: a measured FAIL ---------------------------

    def assert_forbidden_fail(self, response):
        self.assertIs(response["transformedResponse"][KEY], False)
        self.assertEqual(self.collection(response)["status"], "success")
        self.assertEqual(self.collection(response)["errors"], [])
        reasons = response["additionalInfo"]["evaluation"]["failReasons"]
        self.assertEqual(len(reasons), 1)
        self.assertIn("40301", reasons[0])
        self.assertIn("Grant read log", response["additionalInfo"]["evaluation"]["recommendations"][0])
        self.assertEqual(response["additionalInfo"]["transformation"]["inputSummary"]["vendorStatus"], 403)

    def test_access_forbidden_is_a_fail(self):
        self.assert_forbidden_fail(self.run_transform(FORBIDDEN_MARKED))

    def test_access_forbidden_as_json_string(self):
        self.assert_forbidden_fail(self.run_transform(json.dumps(FORBIDDEN_MARKED)))

    def test_access_forbidden_body_as_string(self):
        marked = {"vendorErrorAsResponse": dict(FORBIDDEN_MARKED["vendorErrorAsResponse"],
                                                body=json.dumps(FORBIDDEN_BODY))}
        self.assert_forbidden_fail(self.run_transform(marked))

    def test_access_forbidden_in_enriched_input(self):
        self.assert_forbidden_fail(self.run_transform(
            {"data": FORBIDDEN_MARKED, "validation": {"status": "valid", "errors": [], "warnings": []}}))

    def test_access_forbidden_under_api_response_wrapper(self):
        self.assert_forbidden_fail(self.run_transform({"apiResponse": FORBIDDEN_MARKED}))

    # --- anything else handed over is an error, never judged -------------------

    def assert_data_collection_error(self, response):
        self.assertIs(response["transformedResponse"][KEY], False)
        self.assertEqual(self.collection(response)["status"], "error")
        self.assertEqual(response["additionalInfo"]["evaluation"]["failReasons"], [])

    def test_other_403_code_is_an_error_not_a_fail(self):
        other = {"vendorErrorAsResponse": {"status": 403, "bodyContains": "Access forbidden",
                                           "body": {"code": 40300, "message": "Access forbidden", "stat": "FAIL"}}}
        self.assert_data_collection_error(self.run_transform(other))

    def test_401_with_same_body_is_an_error_not_a_fail(self):
        wrong = {"vendorErrorAsResponse": {"status": 401, "bodyContains": "Access forbidden", "body": FORBIDDEN_BODY}}
        self.assert_data_collection_error(self.run_transform(wrong))

    def test_unparseable_body_is_an_error(self):
        bad = {"vendorErrorAsResponse": {"status": 403, "bodyContains": "Access forbidden", "body": "Access forbidden"}}
        self.assert_data_collection_error(self.run_transform(bad))

    def test_bare_body_without_marker_is_not_treated_as_forbidden(self):
        # Only Integration-Service's marked shape counts; a bare body is zero records.
        response = self.run_transform(FORBIDDEN_BODY)
        self.assertIs(response["transformedResponse"][KEY], False)
        self.assertNotIn("vendorStatus", response["additionalInfo"]["transformation"]["inputSummary"])


if __name__ == "__main__":
    unittest.main()
