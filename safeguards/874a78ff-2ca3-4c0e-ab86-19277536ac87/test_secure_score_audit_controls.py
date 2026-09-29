"""Secure Score audit controls: audit log search (mip_search_auditlog) answers the email-logging criteria;
mailbox auditing (exo_mailboxaudit) answers isMailboxAuditingEnabled only.

J.J. ruling 2026-09-29. A failed call or a missing control must come back as a data-collection error
(Token-Service renders it Unevaluated), never as a measured 0%.
"""
import importlib.util
import unittest
from pathlib import Path


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


audit = load("isauditlogsearchenabled")
mailbox = load("ismailboxauditingenabled")
EMAIL_KEYS = ("isEmailLoggingEnabled", "isEmailSecurityLoggingEnabled")


def scores(*controls):
    return {"value": [{"createdDateTime": "2026-09-29T00:00:00Z", "controlScores": list(controls)}]}


def ctl(name, pct, status=""):
    return {"controlCategory": "Apps", "controlName": name, "score": "0.0", "scoreInPercentage": pct,
            "implementationStatus": status, "lastSynced": "2026-09-29T03:29:36Z"}


# Shape measured on a live tenant 2026-09-29: search on, mailbox audit reported off. Numbers arrive as strings.
LIVE = scores(ctl("mip_search_auditlog", "100.0", "Microsoft 365 audit log search is enabled"),
              ctl("exo_mailboxaudit", "0.0", "Mailbox auditing for all users is disabled"))


def unevaluated(out):
    return out["additionalInfo"]["dataCollection"]["status"] == "error"


class AuditLogSearch(unittest.TestCase):
    def test_enabled_passes_both_email_keys(self):
        out = audit.transform(LIVE)
        for k in EMAIL_KEYS + ("isAuditLogSearchEnabled",):
            self.assertIs(out["transformedResponse"][k], True)
        self.assertFalse(unevaluated(out))

    def test_numeric_100_passes(self):
        out = audit.transform(scores(ctl("mip_search_auditlog", 100.0)))
        self.assertIs(out["transformedResponse"]["isEmailSecurityLoggingEnabled"], True)

    def test_off_is_a_measured_fail(self):
        out = audit.transform(scores(ctl("mip_search_auditlog", "0.0", "audit log search is disabled")))
        for k in EMAIL_KEYS:
            self.assertIs(out["transformedResponse"][k], False)
        self.assertFalse(unevaluated(out))

    def test_no_data_is_unevaluated_not_zero(self):
        for body in ({}, None, "{}", {"value": []}, scores(ctl("exo_mailboxaudit", "0.0")),
                     {"error": {"code": "Authorization_RequestDenied", "message": "Insufficient privileges"}},
                     {"statusCode": 401, "error": "Unauthorized"}, {"PSError": "403 Forbidden"},
                     scores(ctl("mip_search_auditlog", None))):
            out = audit.transform(body)
            for k in EMAIL_KEYS:
                self.assertIs(out["transformedResponse"][k], False, body)
            self.assertTrue(unevaluated(out), body)


class MailboxAudit(unittest.TestCase):
    def test_live_off_is_a_measured_fail(self):
        out = mailbox.transform(LIVE)
        self.assertIs(out["transformedResponse"]["isMailboxAuditingEnabled"], False)
        self.assertFalse(unevaluated(out))

    def test_on_passes(self):
        out = mailbox.transform(scores(ctl("exo_mailboxaudit", "100.0")))
        self.assertIs(out["transformedResponse"]["isMailboxAuditingEnabled"], True)

    def test_no_longer_answers_email_logging(self):
        out = mailbox.transform(scores(ctl("exo_mailboxaudit", "100.0")))
        for k in EMAIL_KEYS:
            self.assertNotIn(k, out["transformedResponse"])

    def test_no_data_is_unevaluated_not_zero(self):
        for body in ({}, None, "{}", {"value": []}, scores(ctl("mip_search_auditlog", "100.0")),
                     {"error": {"code": "Authorization_RequestDenied"}}, {"statusCode": 401, "error": "Unauthorized"},
                     {"PSError": "403 Forbidden"}):
            out = mailbox.transform(body)
            self.assertIs(out["transformedResponse"]["isMailboxAuditingEnabled"], False, body)
            self.assertTrue(unevaluated(out), body)


if __name__ == "__main__":
    unittest.main()
