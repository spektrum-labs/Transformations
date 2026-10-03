"""Google - Email Security isEmailSecurityLoggingEnabled (isemailsecurityloggingenabled.py).

Evidence the definition should route this key to: getGmailLogEvents, the Admin SDK Reports API activity feed for
applicationName=gmail (GET /admin/reports/v1/activity/users/all/applications/gmail?startTime=...&endTime=...),
scope admin.reports.audit.readonly, which the Google - Email Security definition already requests.

The admin-feed fixture follows the real body the current route (checkAuditLogs, applicationName=admin) returned for
the Spektrum Labs tenant on 3 Oct 2026 (identifiers, addresses and IPs replaced). The Gmail fixtures follow the
documented Reports API activity shape for applicationName=gmail.
"""
import importlib.util
import json
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "gmaillogging", Path(__file__).with_name("isemailsecurityloggingenabled.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

KEY = "isEmailSecurityLoggingEnabled"


def stamp(days_ago):
    moment = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (moment.microsecond // 1000)


def activity(app, days_ago, name, parameters):
    return {
        "kind": "admin#reports#activity",
        "id": {"time": stamp(days_ago), "uniqueQualifier": "1000000000000000001",
               "applicationName": app, "customerId": "C0example"},
        "etag": "\"etag-example\"",
        "actor": {"callerType": "USER", "email": "admin@example.com", "profileId": "100000000000000000001"},
        "ipAddress": "192.0.2.10",
        "events": [{"type": "USER_SETTINGS" if app == "admin" else "email", "name": name,
                    "parameters": parameters}],
    }


def feed(*items):
    body = {"kind": "admin#reports#activities", "etag": "\"etag-example\""}
    if items:
        body["items"] = list(items)
    return body


def admin_feed():
    """Shape of the real 3 Oct 2026 checkAuditLogs body: admin console events only."""
    return feed(
        activity("admin", 0.5, "SUSPEND_USER", [{"name": "USER_EMAIL", "value": "user1@example.com"}]),
        activity("admin", 0.6, "CHANGE_PASSWORD", [{"name": "USER_EMAIL", "value": "user2@example.com"}]),
    )


def gmail_event(days_ago):
    return activity("gmail", days_ago, "delivery", [
        {"name": "message_info", "messageValue": {"parameter": [
            {"name": "rfc2822_message_id", "value": "<example@mail.example.com>"},
            {"name": "is_spam", "boolValue": False},
            {"name": "message_set", "multiMessageValue": [{"parameter": [{"name": "type", "intValue": "1"}]}]},
        ]}},
    ])


def run(body):
    out = m.transform(body)
    return out["transformedResponse"], out["additionalInfo"]


class GmailLogging(unittest.TestCase):
    def test_real_admin_feed_is_not_measured(self):
        res, info = run(admin_feed())
        self.assertIs(res[KEY], False)
        self.assertEqual(info["dataCollection"]["status"], "error")
        self.assertIn("admin events, not Gmail log events", info["evaluation"]["failReasons"][0])
        self.assertIn("getGmailLogEvents", info["evaluation"]["recommendations"][0])

    def test_recent_gmail_events_pass(self):
        res, info = run(feed(gmail_event(0.1), gmail_event(1), gmail_event(3)))
        self.assertIs(res[KEY], True)
        self.assertEqual(res["gmailEventsRead"], 3)
        self.assertEqual(info["dataCollection"]["status"], "success")
        self.assertTrue(info["evaluation"]["passReasons"])

    def test_gmail_feed_through_wrappers_and_json_string(self):
        body = {"apiResponse": feed(gmail_event(0.2))}
        res, _ = run(json.dumps(body))
        self.assertIs(res[KEY], True)
        res, _ = run({"data": feed(gmail_event(0.2)), "validation": {"status": "valid", "errors": [], "warnings": []}})
        self.assertIs(res[KEY], True)

    def test_flipped_only_stale_gmail_events_fail(self):
        res, info = run(feed(gmail_event(20), gmail_event(25)))
        self.assertIs(res[KEY], False)
        self.assertEqual(info["dataCollection"]["status"], "success")
        self.assertIn("older than", info["evaluation"]["failReasons"][0])

    def test_empty_gmail_feed_fails(self):
        res, info = run(feed())
        self.assertIs(res[KEY], False)
        self.assertEqual(res["gmailEventsRead"], 0)
        self.assertIn("No Gmail log events", info["evaluation"]["failReasons"][0])

    def test_gmail_events_without_timestamps_fail(self):
        item = gmail_event(0.1)
        del item["id"]["time"]
        res, info = run(feed(item))
        self.assertIs(res[KEY], False)
        self.assertIn("no timestamps", info["evaluation"]["failReasons"][0])

    def test_mixed_feed_reads_only_gmail_events(self):
        res, _ = run(feed(activity("admin", 0.1, "SUSPEND_USER", []), gmail_event(2)))
        self.assertIs(res[KEY], True)
        self.assertEqual(res["gmailEventsRead"], 1)

    def test_empty_body_is_not_measured(self):
        for body in ("", b"", {}, []):
            res, info = run(body)
            self.assertIs(res[KEY], False, body)
            self.assertEqual(info["dataCollection"]["status"], "error", body)

    def test_none_is_not_measured(self):
        res, info = run(None)
        self.assertIs(res[KEY], False)
        self.assertEqual(info["dataCollection"]["status"], "error")
        self.assertIn("No response body", info["evaluation"]["failReasons"][0])

    def test_google_scope_error_is_named(self):
        res, info = run({"error": {"code": 403, "status": "PERMISSION_DENIED",
                                   "message": "Request had insufficient authentication scopes."}})
        self.assertIs(res[KEY], False)
        self.assertEqual(info["dataCollection"]["status"], "error")
        self.assertIn("scope not granted", info["evaluation"]["failReasons"][0])

    def test_integration_error_envelope_is_not_measured(self):
        res, info = run({"statusCode": 500, "message": "Upstream timeout"})
        self.assertIs(res[KEY], False)
        self.assertEqual(info["dataCollection"]["status"], "error")

    def test_unparseable_string_fails_closed(self):
        res, info = run("{not json")
        self.assertIs(res[KEY], False)
        self.assertEqual(info["transformation"]["status"], "error")


if __name__ == "__main__":
    unittest.main()
