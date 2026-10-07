"""ThreatDown isEPPEnabled / requiredCoveragePercentage (from getEndpoints, in isrealtimeprotectionenabled.py)
and isEPPLoggingEnabled (from getEvents). Shapes follow the Nebula OpenAPI and the live Trebron read of
2026-09-28 (2 judged endpoints, both Protected)."""
import copy
import importlib.util
import unittest
from pathlib import Path

HERE = Path(__file__).parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def endpoint(name, status="Protected", day="2026-09-28", deleted=False):
    return {"display_name": name, "protection_status": status,
            "machine": {"id": name, "last_day_seen": day, "is_deleted": deleted}}


ENDPOINTS = {"endpoints": [endpoint("a"), endpoint("b")]}
EVENTS = {"events": [{"id": "1", "machine_id": "a", "type_name": "Scan", "severity_name": "info",
                      "timestamp": "2026-09-28T10:00:00Z"}], "total_count": 1, "next_cursor": ""}
RELAY_401 = {"result": {"errorMessage": "Unauthorized", "vendorStatus": 401}}
NOTHING = [{}, None, "{}", {"error": True, "errorMessage": "Unauthorized"}, RELAY_401]


class EndpointKeys(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = load("isrealtimeprotectionenabled")

    def out(self, payload):
        return self.t.transform(payload)["transformedResponse"]

    def test_all_protected(self):
        out = self.out(ENDPOINTS)
        self.assertIs(out["isEPPEnabled"], True)
        self.assertEqual(out["requiredCoveragePercentage"], 100)
        self.assertIs(out["isRealTimeProtectionEnabled"], True)

    def test_coverage_rounds_down(self):
        body = {"endpoints": [endpoint(str(i)) for i in range(199)] + [endpoint("x", "Scan Only")]}
        out = self.out(body)
        self.assertEqual(out["requiredCoveragePercentage"], 99)
        self.assertIs(out["isEPPEnabled"], False)

    def test_half_unprotected(self):
        body = copy.deepcopy(ENDPOINTS)
        body["endpoints"][1]["protection_status"] = "Unprotected"
        out = self.out(body)
        self.assertEqual(out["requiredCoveragePercentage"], 50)
        self.assertIs(out["isEPPEnabled"], False)

    def test_no_judged_endpoint(self):
        out = self.out({"endpoints": []})
        self.assertEqual(out["requiredCoveragePercentage"], 0)
        self.assertIs(out["isEPPEnabled"], False)

    def test_bodies_that_prove_nothing(self):
        for body in NOTHING:
            out = self.out(body)
            self.assertIs(out["isEPPEnabled"], False, body)
            self.assertEqual(out["requiredCoveragePercentage"], 0, body)


class LoggingKey(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = load("isepploggingenabled")

    def out(self, payload):
        return self.t.transform(payload)["transformedResponse"]

    def test_events_present(self):
        out = self.out(EVENTS)
        self.assertIs(out["isEPPLoggingEnabled"], True)
        self.assertEqual(out["eventCount"], 1)
        self.assertEqual(out["totalCount"], 1)

    def test_empty_collection_fails(self):
        out = self.out({"events": [], "total_count": 0, "next_cursor": ""})
        self.assertIs(out["isEPPLoggingEnabled"], False)
        self.assertEqual(out["eventCount"], 0)

    def test_wrapped_bare_list(self):
        self.assertIs(self.out({"apiResponse": EVENTS["events"]})["isEPPLoggingEnabled"], True)

    def test_bodies_that_prove_nothing(self):
        for body in NOTHING + [{"events": "x"}, {"statusCode": 403, "message": "Forbidden"}]:
            self.assertIs(self.out(body)["isEPPLoggingEnabled"], False, body)


if __name__ == "__main__":
    unittest.main()
