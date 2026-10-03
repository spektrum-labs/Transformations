"""isUnifiedAuditLoggingEnabled reads the Admin SDK Reports API admin activity feed (checkAuditLogs).

Fixture shape mirrors a stored Workspace admin feed read (2026-10-01), with every id, email and etag replaced
by synthetic values: kind admin#reports#activities, items of kind admin#reports#activity with
id.applicationName "admin", newest first, and a nextPageToken because more events exist.
"""
import copy
import importlib.util
import json
import unittest
from pathlib import Path

PATH = Path(__file__).with_name("isunifiedauditloggingenabled.py")
KEY = "isUnifiedAuditLoggingEnabled"


def load():
    spec = importlib.util.spec_from_file_location("isunifiedauditloggingenabled", PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def activity(time, app="admin", name="CHANGE_APPLICATION_SETTING"):
    return {"kind": "admin#reports#activity",
            "id": {"time": time, "uniqueQualifier": "-1000000000000000001", "applicationName": app,
                   "customerId": "C0synthetic"},
            "etag": "\"synthetic-etag\"",
            "actor": {"callerType": "USER", "email": "admin@example.com", "profileId": "100000000000000000001"},
            "isAgenticAction": "False",
            "events": [{"type": "APPLICATION_SETTINGS", "name": name,
                        "parameters": [{"name": "APPLICATION_NAME", "value": "Gmail"}]}]}


REAL = {"kind": "admin#reports#activities", "etag": "\"synthetic-etag\"",
        "items": [activity("2026-10-01T16:37:00.014Z"), activity("2026-09-30T09:12:44.501Z", name="CREATE_USER"),
                  activity("2026-09-28T22:01:03.000Z", name="USER_LICENSE_ASSIGNMENT")],
        "nextPageToken": "synthetic-next-page"}


def ts_is_equals_true(value):
    return value is True


class AdminAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = load()

    def run_t(self, body):
        out = self.t.transform(body)
        return out["transformedResponse"][KEY], out

    def assert_unevaluated(self, body):
        value, out = self.run_t(body)
        self.assertIsNone(value, out)
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "error")
        self.assertTrue(out["additionalInfo"]["dataCollection"]["errors"])
        self.assertFalse(ts_is_equals_true(value))
        return out

    # real shape
    def test_real_admin_feed_is_true(self):
        value, out = self.run_t(REAL)
        self.assertIs(value, True)
        self.assertTrue(ts_is_equals_true(value))
        self.assertEqual(out["transformedResponse"]["adminAuditEventsRead"], 3)
        summary = out["additionalInfo"]["transformation"]["inputSummary"]
        self.assertEqual(summary["newestAdminEvent"], "2026-10-01T16:37:00Z")
        self.assertTrue(summary["morePages"])
        self.assertNotIn("admin@example.com", json.dumps(out))

    def test_real_shape_as_string_bytes_and_wrapped(self):
        self.assertIs(self.run_t(json.dumps(REAL))[0], True)
        self.assertIs(self.run_t(json.dumps(REAL).encode("utf-8"))[0], True)
        self.assertIs(self.run_t({"result": {"apiResponse": copy.deepcopy(REAL)}})[0], True)
        self.assertIs(self.run_t({"_response_data": copy.deepcopy(REAL)})[0], True)

    def test_without_next_page_still_true(self):
        body = copy.deepcopy(REAL)
        del body["nextPageToken"]
        self.assertIs(self.run_t(body)[0], True)

    # flipped: the feed of another application is not the admin audit log
    def test_flipped_gmail_feed_is_unevaluated(self):
        body = copy.deepcopy(REAL)
        for item in body["items"]:
            item["id"]["applicationName"] = "gmail"
        out = self.assert_unevaluated(body)
        self.assertIn("not admin audit events", out["additionalInfo"]["dataCollection"]["errors"][0])

    def test_mixed_feed_is_unevaluated(self):
        body = copy.deepcopy(REAL)
        body["items"].append(activity("2026-09-27T10:00:00.000Z", app="login"))
        self.assert_unevaluated(body)

    def test_admin_feed_with_no_events_is_unevaluated_never_false(self):
        for body in [{"kind": "admin#reports#activities", "etag": "\"e\""},
                     {"kind": "admin#reports#activities", "items": []}]:
            out = self.assert_unevaluated(body)
            self.assertIn("no events", out["additionalInfo"]["dataCollection"]["errors"][0])

    # empty / None / error / partial / unrelated
    def test_empty_inputs_are_unevaluated(self):
        for body in [{}, "{}", "", b"", "  ", [], {"result": {}}, {"items": []}]:
            self.assert_unevaluated(body)

    def test_none_is_unevaluated(self):
        self.assert_unevaluated(None)

    def test_error_bodies_are_unevaluated(self):
        scope = {"error": {"code": 403, "message": "Request had insufficient authentication scopes.",
                           "status": "PERMISSION_DENIED"}}
        out = self.assert_unevaluated(scope)
        self.assertIn("admin.reports.audit.readonly", out["additionalInfo"]["dataCollection"]["errors"][0])
        for body in [{"error": {"code": 401, "message": "Login Required.", "status": "UNAUTHENTICATED"}},
                     {"statusCode": 401, "error": "Unauthorized"}, {"status_code": 403, "error": "Forbidden"},
                     {"error": {"statusCode": 401, "message": "Unauthorized"}},
                     {"status": "Error", "message": "Integrator not configured"},
                     {"kind": "admin#reports#activities", "statusCode": 500, "message": "backend error"}]:
            self.assert_unevaluated(body)

    def test_partial_or_unreadable_records_are_unevaluated(self):
        no_time = copy.deepcopy(REAL)
        del no_time["items"][1]["id"]["time"]
        self.assert_unevaluated(no_time)
        no_id = copy.deepcopy(REAL)
        del no_id["items"][0]["id"]
        self.assert_unevaluated(no_id)
        junk = copy.deepcopy(REAL)
        junk["items"].append("truncated")
        self.assert_unevaluated(junk)
        bad_time = copy.deepcopy(REAL)
        bad_time["items"][2]["id"]["time"] = "yesterday"
        self.assert_unevaluated(bad_time)
        not_list = copy.deepcopy(REAL)
        not_list["items"] = {"0": REAL["items"][0]}
        self.assert_unevaluated(not_list)

    def test_unrelated_bodies_are_unevaluated(self):
        for body in [{"hello": "world"}, {"foo": {"bar": [1, 2, 3]}},
                     {"kind": "admin#reports#activity", "id": REAL["items"][0]["id"]},
                     {"kind": "admin#directory#users", "users": []},
                     {"policies": [{"setting": {"type": "settings/security.less_secure_apps"}}]}]:
            self.assert_unevaluated(body)

    def test_transformation_error_is_unevaluated(self):
        original = self.t.parse_time
        try:
            self.t.parse_time = lambda value: (_ for _ in ()).throw(RuntimeError("boom"))
            out = self.assert_unevaluated(copy.deepcopy(REAL))
            self.assertEqual(out["additionalInfo"]["transformation"]["status"], "error")
        finally:
            self.t.parse_time = original

    def test_no_measured_false_exists(self):
        for body in [REAL, {}, None, {"hello": "world"}, {"kind": "admin#reports#activities"}]:
            self.assertIsNot(self.run_t(copy.deepcopy(body))[0], False)


if __name__ == "__main__":
    unittest.main()
