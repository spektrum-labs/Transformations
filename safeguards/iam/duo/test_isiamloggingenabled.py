"""isIAMLoggingEnabled (isiamloggingenabled.py): Duo v1 and v2 authentication log shapes.

v1 getAuthenticationLogs hands over {"stat": "OK", "response": [...]} with "username" on each event;
v2 getAuthLogs hands over {"authlogs": [...], "metadata": {...}} with the user under user.name. Both
must read the same way, and the evidence must name the endpoint the events came from and the real time
span of the events read. 403 / 40301 stays a measured False; any other error or an empty body is a
data-collection error, never judged. Synthetic data only.
"""
import importlib.util
import json
import unittest
from pathlib import Path

TRANSFORMATION_PATH = Path(__file__).with_name("isiamloggingenabled.py")
KEY = "isIAMLoggingEnabled"

FORBIDDEN_BODY = {"code": 40301, "message": "Access forbidden", "stat": "FAIL"}
FORBIDDEN_MARKED = {"vendorErrorAsResponse": {
    "status": 403, "bodyContains": "Access forbidden", "body": FORBIDDEN_BODY}}

V1_EVENTS = [
    {"txid": "a1", "timestamp": 1790000000, "username": "u1", "factor": "duo_push", "result": "success"},
    {"txid": "a2", "timestamp": 1790000100, "username": "u2", "factor": "passcode", "result": "denied"},
]
V2_EVENTS = [
    {"txid": "b1", "timestamp": 1790500000, "user": {"name": "u1", "key": "k1"}, "factor": "duo_push",
     "result": "success", "event_type": "authentication"},
    {"txid": "b2", "timestamp": 1790000000, "user": {"name": "u3", "key": "k3"}, "factor": "passcode",
     "result": "denied", "event_type": "authentication"},
    {"txid": "b3", "timestamp": 1790200000, "user": {"name": "u1", "key": "k1"}, "factor": "duo_push",
     "result": "success", "event_type": "authentication"},
]
V2_BODY = {"authlogs": V2_EVENTS, "metadata": {"next_offset": None,
                                               "total_objects": {"value": 3, "relation": "eq"}}}


def load_transformation():
    spec = importlib.util.spec_from_file_location("duo_isiamloggingenabled", TRANSFORMATION_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DuoIAMLoggingShapesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = load_transformation()

    def evaluation(self, response):
        return response["additionalInfo"]["evaluation"]

    def summary(self, response):
        return response["additionalInfo"]["transformation"]["inputSummary"]

    def collection(self, response):
        return response["additionalInfo"]["dataCollection"]

    def test_v1_shape_passes_and_cites_the_v1_endpoint_and_span(self):
        response = self.t.transform({"stat": "OK", "response": V1_EVENTS})
        self.assertIs(response["transformedResponse"][KEY], True)
        self.assertEqual(response["transformedResponse"]["loggedUserCount"], 2)
        reason = self.evaluation(response)["passReasons"][0]
        self.assertIn("/admin/v1/logs/authentication", reason)
        self.assertIn("from 2026-09-21T14:13:20+00:00 to 2026-09-21T14:15:00+00:00", reason)
        self.assertEqual(self.summary(response)["endpoint"], "/admin/v1/logs/authentication")

    def test_v2_shape_passes_and_cites_the_v2_endpoint_and_span(self):
        response = self.t.transform(V2_BODY)
        out = response["transformedResponse"]
        self.assertIs(out[KEY], True)
        self.assertEqual(out["authLogEventCount"], 3)
        self.assertEqual(out["completeEventCount"], 3)
        self.assertEqual(out["loggedUserCount"], 2)
        reason = self.evaluation(response)["passReasons"][0]
        self.assertIn("/admin/v2/logs/authentication", reason)
        self.assertNotIn("/admin/v1/", reason)
        self.assertIn("from 2026-09-21T14:13:20+00:00 to 2026-09-27T09:06:40+00:00", reason)
        summary = self.summary(response)
        self.assertEqual(summary["endpoint"], "/admin/v2/logs/authentication")
        self.assertEqual(summary["oldestEventTimestamp"], "2026-09-21T14:13:20+00:00")
        self.assertEqual(summary["newestEventTimestamp"], "2026-09-27T09:06:40+00:00")

    def test_raw_v2_body_and_wrappers(self):
        for payload in ({"stat": "OK", "response": V2_BODY}, {"apiResponse": V2_BODY}, json.dumps(V2_BODY),
                        {"data": V2_BODY, "validation": {"status": "valid", "errors": [], "warnings": []}}):
            with self.subTest(payload=str(payload)[:40]):
                self.assertIs(self.t.transform(payload)["transformedResponse"][KEY], True)

    def test_v2_events_without_user_name_cannot_be_attributed(self):
        stripped = [{k: v for k, v in e.items() if k != "user"} for e in V2_EVENTS]
        response = self.t.transform({"authlogs": stripped, "metadata": {}})
        self.assertIs(response["transformedResponse"][KEY], False)
        self.assertIn("/admin/v2/logs/authentication", self.evaluation(response)["failReasons"][0])

    def test_empty_bodies_are_data_collection_errors_not_judged(self):
        for payload in ({"authlogs": [], "metadata": {}}, {"stat": "OK", "response": []}, {}, None, "not json"):
            with self.subTest(payload=payload):
                response = self.t.transform(payload)
                self.assertIs(response["transformedResponse"][KEY], False)
                self.assertEqual(self.collection(response)["status"], "error")
                self.assertEqual(self.evaluation(response)["failReasons"], [])

    def test_access_forbidden_is_a_measured_false(self):
        response = self.t.transform(FORBIDDEN_MARKED)
        self.assertIs(response["transformedResponse"][KEY], False)
        self.assertEqual(self.collection(response)["status"], "success")
        self.assertIn("40301", self.evaluation(response)["failReasons"][0])

    def test_other_vendor_error_is_a_data_collection_error(self):
        other = {"vendorErrorAsResponse": {"status": 403, "bodyContains": "Access forbidden",
                                           "body": {"code": 40300, "message": "Access forbidden"}}}
        response = self.t.transform(other)
        self.assertEqual(self.collection(response)["status"], "error")
        self.assertEqual(self.evaluation(response)["failReasons"], [])


if __name__ == "__main__":
    unittest.main()
