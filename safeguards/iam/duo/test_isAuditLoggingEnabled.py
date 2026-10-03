"""isAuditLoggingEnabled: recency of Duo administrator log events (GET /admin/v1/logs/administrator).

A non-empty list used to pass, and "most recent" was the FIRST entry. getAdminLogs sends mintime=1 and
limit=1000, so a window cut at the limit may never have read the newest events. Now: newest = max
timestamp; <= 30 days True; 30-90 days Unevaluated; > 90 days False on a complete read; a read at the
1000 limit with newest > 30 days is Unevaluated; errors and unreadable input are Unevaluated, never False.
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
DAY = 86400

FORBIDDEN_BODY = {"code": 40301, "message": "Access forbidden", "stat": "FAIL"}
FORBIDDEN_MARKED = {"vendorErrorAsResponse": {
    "status": 403, "bodyContains": "Access forbidden", "body": FORBIDDEN_BODY}}


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


class DuoAuditLoggingRecencyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = load_transformation()

    def setUp(self):
        self.t.now_utc = lambda: NOW

    def run_transform(self, payload):
        return self.t.transform(payload)

    def value(self, payload):
        return self.run_transform(payload)["transformedResponse"][KEY]

    def assert_unevaluated(self, response):
        self.assertIsNone(response["transformedResponse"][KEY])
        self.assertEqual(response["additionalInfo"]["dataCollection"]["status"], "error")

    # --- the three bands -------------------------------------------------------

    def test_newest_two_days_old_passes(self):
        response = self.run_transform(body([entry(2), entry(200)]))
        self.assertIs(response["transformedResponse"][KEY], True)
        self.assertEqual(response["transformedResponse"]["newestEventAgeDays"], 2)
        self.assertTrue(response["additionalInfo"]["evaluation"]["passReasons"])

    def test_newest_45_days_old_is_unevaluated(self):
        response = self.run_transform(body([entry(45), entry(300)]))
        self.assert_unevaluated(response)
        reason = response["additionalInfo"]["evaluation"]["failReasons"][0]
        self.assertIn("45 days old (more than 30)", reason)

    def test_newest_120_days_old_complete_read_fails(self):
        response = self.run_transform(body([entry(120), entry(400)]))
        self.assertIs(response["transformedResponse"][KEY], False)
        self.assertIn("no administrator log events in the last 90 days",
                      response["additionalInfo"]["evaluation"]["failReasons"][0])

    def test_empty_list_is_unevaluated_not_a_fail(self):
        # getAdminLogs' returnSpec defaults an unreadable body to [], so an empty list may be a
        # failed read; a Duo account also always logs its own administrator activity.
        for payload in (body([]), []):
            with self.subTest(payload=payload):
                self.assertIsNone(self.value(payload))

    # --- truncation at the request limit --------------------------------------

    def test_1000_entries_all_400_days_old_is_unevaluated(self):
        rows = [entry(400, i) for i in range(1000)]
        response = self.run_transform(body(rows))
        self.assert_unevaluated(response)
        self.assertIn("may not have been read", response["additionalInfo"]["evaluation"]["failReasons"][0])

    def test_1000_entries_year_old_first_entry_but_nothing_recent_is_not_a_pass(self):
        # The customer case: exactly 1000 entries, first timestamp a year old.
        rows = [entry(365)] + [entry(366 + i % 30) for i in range(999)]
        self.assertIsNone(self.value(body(rows)))

    def test_1000_entries_newest_10_days_old_passes(self):
        rows = [entry(10 + i % 300) for i in range(1000)]
        self.assertIs(self.value(body(rows)), True)

    def test_1000_entries_45_days_old_and_999_entries_120_days_old(self):
        self.assertIsNone(self.value(body([entry(45 + i) for i in range(1000)])))
        self.assertIs(self.value(body([entry(120 + i) for i in range(999)])), False)

    # --- max(), not first -------------------------------------------------------

    def test_ordering_does_not_matter(self):
        rows = [entry(d) for d in (1, 40, 100, 200, 365)]
        shuffled = list(rows)
        random.Random(7).shuffle(shuffled)
        for label, ordered in (("newest first", rows), ("newest last", rows[::-1]), ("shuffled", shuffled)):
            with self.subTest(order=label):
                self.assertIs(self.value(body(ordered)), True)
        stale = [entry(d) for d in (120, 200, 365)]
        for ordered in (stale, stale[::-1]):
            self.assertIs(self.value(body(ordered)), False)

    # --- timestamp forms -------------------------------------------------------

    def test_mixed_timestamp_and_isotimestamp_entries(self):
        rows = [entry(200), entry(3, iso_only=True), entry(100)]
        self.assertIs(self.value(body(rows)), True)
        rows = [entry(3, iso_only=False), entry(200, iso_only=True)]
        self.assertIs(self.value(body(rows)), True)
        rows = [entry(150, iso_only=True), entry(130)]
        self.assertIs(self.value(body(rows)), False)

    def test_isotimestamp_variants(self):
        row = {"username": "a", "action": "x", "isotimestamp": "2026-10-01T10:00:00.000000+00:00"}
        self.assertIs(self.value(body([row])), True)
        row = {"username": "a", "action": "x", "isotimestamp": "2026-10-01T10:00:00Z"}
        self.assertIs(self.value(body([row])), True)

    def test_entries_without_a_valid_timestamp_are_ignored(self):
        junk = [{"username": "a", "action": "x"}, {"timestamp": "soon"}, {"timestamp": None, "isotimestamp": "bad"},
                {"timestamp": True}, "text", None, 5, {"timestamp": -3}]
        self.assertIs(self.value(body(junk + [entry(2)])), True)
        self.assertIsNone(self.value(body(junk)))  # nothing usable: cannot judge, never False

    # --- boundaries ----------------------------------------------------------

    def test_exactly_30_days_is_a_pass_and_just_over_is_not(self):
        self.assertIs(self.value(body([entry(30)])), True)
        self.assertIsNone(self.value(body([entry(30, 1)])))

    def test_exactly_90_days_is_unevaluated_and_just_over_fails(self):
        self.assertIsNone(self.value(body([entry(90)])))
        self.assertIs(self.value(body([entry(90, 1)])), False)

    # --- future-dated entries --------------------------------------------------

    def test_future_entry_does_not_rescue_a_stale_list(self):
        future = entry(-5)  # five days ahead
        self.assertIs(self.value(body([entry(200), future])), False)
        self.assertIsNone(self.value(body([entry(45), future])))
        self.assertIsNone(self.value(body([future])))

    def test_small_clock_skew_still_counts(self):
        self.assertIs(self.value(body([entry(0, -3600)])), True)  # one hour ahead

    # --- unreadable input is Unevaluated, never False ---------------------------

    def test_unreadable_inputs_are_unevaluated(self):
        payloads = {
            "None": None,
            "non-list": {"stat": "OK", "response": "nope"},
            "number": 42,
            "string": "not json",
            "empty dict": {},
            "marker 403": FORBIDDEN_MARKED,
            "marker 500": {"vendorErrorAsResponse": {"status": 500, "body": "boom"}},
            "error body": {"stat": "FAIL", "code": 40101, "message": "Invalid signature"},
            "error key": {"error": "unauthorized"},
            "json null": "null",
            "wrapped marker": {"response": FORBIDDEN_MARKED},
        }
        for label, payload in payloads.items():
            with self.subTest(case=label):
                response = self.run_transform(payload)
                self.assert_unevaluated(response)
                self.assertTrue(response["additionalInfo"]["evaluation"]["failReasons"])

    def test_validation_failure_is_unevaluated(self):
        payload = {"data": [entry(1)], "validation": {"status": "failed", "errors": ["x"], "warnings": []}}
        self.assert_unevaluated(self.run_transform(payload))

    def test_exception_is_unevaluated_not_false(self):
        def boom():
            raise RuntimeError("clock broke")
        self.t.now_utc = boom
        response = self.run_transform(body([entry(1)]))
        self.assertIsNone(response["transformedResponse"][KEY])
        self.assertEqual(response["additionalInfo"]["transformation"]["status"], "error")

    def test_json_string_and_bytes_inputs(self):
        payload = json.dumps(body([entry(2)]))
        self.assertIs(self.value(payload), True)
        self.assertIs(self.value(payload.encode("utf-8")), True)

    def test_flip_stale_never_passes(self):
        for days in (31, 60, 91, 400):
            with self.subTest(days=days):
                self.assertIsNot(self.value(body([entry(days)])), True)


if __name__ == "__main__":
    unittest.main()
