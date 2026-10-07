"""isAuditLoggingEnabled: Duo's administrator audit log is readable (GET /admin/v1/logs/administrator).

getAdminLogs sends mintime = now - 30 days, so every event Duo returns is inside the last 30 days, and
Duo v1 returns at most the EARLIEST 1000 events of that window (oldest first). Duo records administrator
actions for every account with no setting to turn it off, so:

  * a successful read passes, empty or not (an empty window is no administrator activity, not a gap);
  * an error, a vendor error marker or an unreadable body is Not evaluated (value None, data-collection
    error), never False;
  * the evidence names the window, the oldest and newest event read, and readMayBeTruncated, and a read at
    the 1000-event limit says the newest event read is not the newest in the window.
"""
import importlib.util
import json
import random
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

TRANSFORMATION_PATH = Path(__file__).with_name("isAuditLoggingEnabled.py")
KEY = "isAuditLoggingEnabled"
NOW = datetime(2026, 10, 3, 12, 0, 0, tzinfo=timezone.utc)

FORBIDDEN_BODY = {"code": 40301, "message": "Access forbidden", "stat": "FAIL"}
FORBIDDEN_MARKED = {"vendorErrorAsResponse": {
    "status": 403, "bodyContains": "Access forbidden", "body": FORBIDDEN_BODY}}
# What Integration-Service hands a transform after a vendor HTTP error (format_error_response).
IS_ERROR_ENVELOPE = {"integrationName": "Duo", "errorMessage": "Invalid signature in request credentials",
                     "error": True, "status": "Error", "statusCode": 401, "vendorStatus": 401}


def load_transformation():
    spec = importlib.util.spec_from_file_location("duo_isAuditLoggingEnabled", TRANSFORMATION_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def entry(days_ago, seconds_extra=0, iso_only=False):
    when = NOW - timedelta(days=days_ago, seconds=seconds_extra)
    row = {"username": "admin@example.com", "action": "user_update", "object": "jdoe",
           "description": json.dumps({"name": "J Doe"})}
    if iso_only:
        row["isotimestamp"] = when.isoformat().replace("+00:00", "Z")
    else:
        row["timestamp"] = int(when.timestamp())
        row["isotimestamp"] = when.isoformat()
    return row


def body(rows):
    return {"stat": "OK", "response": rows}


def returned(rows):
    """The shape getAdminLogs' returnSpec hands the transform: {"response": [...]}."""
    return {"response": rows}


class DuoAuditLoggingReadableLogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = load_transformation()

    def setUp(self):
        self.t.now_utc = lambda: NOW

    def run_transform(self, payload):
        return self.t.transform(payload)

    def value(self, payload):
        return self.run_transform(payload)["transformedResponse"][KEY]

    def evaluation(self, response):
        return response["additionalInfo"]["evaluation"]

    def assert_pass(self, response):
        self.assertIs(response["transformedResponse"][KEY], True)
        self.assertEqual(response["additionalInfo"]["dataCollection"]["status"], "success")
        self.assertEqual(self.evaluation(response)["failReasons"], [])

    def assert_unevaluated(self, response):
        self.assertIsNone(response["transformedResponse"][KEY])
        self.assertEqual(response["additionalInfo"]["dataCollection"]["status"], "error")
        self.assertTrue(response["additionalInfo"]["dataCollection"]["errors"])

    # --- success, empty: a pass ----------------------------------------------------

    def test_success_empty_window_passes(self):
        for payload in (returned([]), body([]), {"data": returned([]), "validation": {"status": "valid"}}):
            with self.subTest(payload=payload):
                response = self.run_transform(payload)
                self.assert_pass(response)
                out = response["transformedResponse"]
                self.assertEqual(out["totalLogCount"], 0)
                self.assertIs(out["logsPresent"], False)
                self.assertIs(out["readMayBeTruncated"], False)
                self.assertEqual(out["windowDays"], 30)
                self.assertIsNone(out["mostRecentTimestamp"])
                reason = self.evaluation(response)["passReasons"][0]
                self.assertIn("no events", reason)
                self.assertIn("last 30 days", reason)
                self.assertIn("/admin/v1/logs/administrator", reason)

    # --- success, non-empty: a pass, with the latest event and the window ---------

    def test_success_non_empty_passes_and_reports_latest_event(self):
        rows = [entry(20), entry(2), entry(9)]
        response = self.run_transform(returned(rows))
        self.assert_pass(response)
        out = response["transformedResponse"]
        self.assertEqual(out["totalLogCount"], 3)
        self.assertEqual(out["mostRecentTimestamp"], (NOW - timedelta(days=2)).isoformat())
        self.assertEqual(out["oldestTimestamp"], (NOW - timedelta(days=20)).isoformat())
        self.assertEqual(out["newestEventAgeDays"], 2)
        self.assertIs(out["readMayBeTruncated"], False)
        reason = self.evaluation(response)["passReasons"][0]
        self.assertIn("latest administrator event is " + out["mostRecentTimestamp"], reason)
        self.assertIn("last 30 days", reason)
        findings = self.evaluation(response)["additionalFindings"]
        self.assertTrue(any(f.startswith("Window read: the last 30 days") for f in findings))
        self.assertTrue(any(f.startswith("Latest administrator event: ") for f in findings))

    def test_ordering_does_not_matter(self):
        rows = [entry(d) for d in (29, 1, 15, 7, 22)]
        expected = (NOW - timedelta(days=1)).isoformat()
        for seed in range(5):
            shuffled = list(rows)
            random.Random(seed).shuffle(shuffled)
            with self.subTest(seed=seed):
                self.assertEqual(self.run_transform(returned(shuffled))["transformedResponse"]["mostRecentTimestamp"],
                                 expected)

    def test_isotimestamp_only_entries(self):
        response = self.run_transform(returned([entry(3, iso_only=True), entry(12, iso_only=True)]))
        self.assert_pass(response)
        self.assertEqual(response["transformedResponse"]["newestEventAgeDays"], 3)

    def test_events_older_than_the_window_still_pass(self):
        # mintime keeps these out today; if it ever widens, a readable log is still a pass.
        self.assert_pass(self.run_transform(returned([entry(120), entry(400)])))

    def test_never_false(self):
        for rows in ([], [entry(1)], [entry(45)], [entry(400)], [entry(1)] * 1000):
            with self.subTest(n=len(rows)):
                self.assertIsNot(self.value(returned(rows)), False)

    # --- a read at Duo's 1000-event limit: honest about what was not read ---------

    def test_read_at_the_limit_flags_truncation_and_says_newer_events_were_not_read(self):
        rows = [entry(29, seconds_extra=i) for i in range(999)] + [entry(18)]
        response = self.run_transform(returned(rows))
        self.assert_pass(response)
        out = response["transformedResponse"]
        self.assertIs(out["readMayBeTruncated"], True)
        self.assertEqual(out["totalLogCount"], 1000)
        self.assertEqual(out["mostRecentTimestamp"], (NOW - timedelta(days=18)).isoformat())
        reason = self.evaluation(response)["passReasons"][0]
        self.assertIn("earliest 1000 events", reason)
        self.assertIn("newer events may exist that were not read", reason)
        findings = self.evaluation(response)["additionalFindings"]
        self.assertTrue(any("not the newest in the window" in f for f in findings))

    def test_999_entries_is_not_flagged_truncated(self):
        out = self.run_transform(returned([entry(5)] * 999))["transformedResponse"]
        self.assertIs(out["readMayBeTruncated"], False)

    def test_read_may_be_truncated_reaches_the_evidence(self):
        self.assertIn("readMayBeTruncated", self.t.RESULT_KEYS)
        response = self.run_transform(returned([entry(5)] * 1000))
        self.assertIn("readMayBeTruncated", response["additionalInfo"]["transformation"]["inputSummary"])

    # --- errors and unreadable bodies: Not evaluated -------------------------------

    def test_error_envelope_is_not_evaluated(self):
        payloads = {
            "IS error envelope": IS_ERROR_ENVELOPE,
            "IS error envelope under apiResponse": {"apiResponse": IS_ERROR_ENVELOPE},
            "marker 403": FORBIDDEN_MARKED,
            "marker 500": {"vendorErrorAsResponse": {"status": 500, "body": "boom"}},
            "wrapped marker": {"response": FORBIDDEN_MARKED},
            "Duo error body": {"stat": "FAIL", "code": 40101, "message": "Invalid signature"},
            "error key": {"error": "unauthorized"},
            "status Error": {"status": "Error", "message": "rate limited"},
        }
        for label, payload in payloads.items():
            with self.subTest(case=label):
                response = self.run_transform(payload)
                self.assert_unevaluated(response)
                self.assertTrue(self.evaluation(response)["failReasons"])

    def test_an_explicit_false_or_null_error_key_is_not_an_error(self):
        for flag in (False, None):
            with self.subTest(error=flag):
                self.assert_pass(self.run_transform({"error": flag, "response": [entry(3)]}))

    def test_unreadable_inputs_are_not_evaluated(self):
        payloads = {
            "None": None,
            "non-list": {"stat": "OK", "response": "nope"},
            "number": 42,
            "string": "not json",
            "empty dict": {},
            "json null": "null",
            "entries without timestamps": returned([{"action": "x", "username": "y"}]),
            "entries not objects": returned(["a", "b"]),
            "only future timestamps": returned([entry(-5)]),
        }
        for label, payload in payloads.items():
            with self.subTest(case=label):
                self.assert_unevaluated(self.run_transform(payload))

    def test_validation_failure_is_not_evaluated(self):
        payload = {"data": [entry(1)], "validation": {"status": "failed", "errors": ["x"], "warnings": []}}
        self.assert_unevaluated(self.run_transform(payload))

    def test_exception_is_not_evaluated_not_false(self):
        def boom():
            raise RuntimeError("clock broke")
        self.t.now_utc = boom
        response = self.run_transform(returned([entry(1)]))
        self.assertIsNone(response["transformedResponse"][KEY])
        self.assertEqual(response["additionalInfo"]["transformation"]["status"], "error")
        self.assertEqual(response["additionalInfo"]["dataCollection"]["status"], "error")

    def test_json_string_and_bytes_inputs(self):
        payload = json.dumps(returned([entry(2)]))
        self.assertIs(self.value(payload), True)
        self.assertIs(self.value(payload.encode("utf-8")), True)

    def test_docstring_matches_the_live_mintime(self):
        doc = self.t.__doc__
        self.assertIn("{$utcNowS-30d}", doc)
        self.assertNotIn("mintime=1", doc)


if __name__ == "__main__":
    unittest.main()
