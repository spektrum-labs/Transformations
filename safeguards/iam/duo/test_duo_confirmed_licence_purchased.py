"""Duo confirmedLicensePurchased reads the edition from GET /admin/v1/info/summary.

Paid edition -> True (reason: edition as reported by Duo, Duo includes trials); Duo Free or an edition containing "trial" -> False; a 403 refusal names the Admin API permission;
no edition field is coded NOT-AVAILABLE; anything unreadable is Not evaluated (None + dataCollection error).
Every case also runs in the RestrictedPython sandbox production uses. Synthetic bodies only.
"""
import importlib.util
import json
import unittest
from pathlib import Path

PATH = Path(__file__).with_name("confirmedLicensePurchased.py")
ROOT = Path(__file__).resolve().parents[3]
KEY = "confirmedLicensePurchased"


def summary(edition):
    body = {"admin_count": 3, "integration_count": 4, "telephony_credits_remaining": 100,
            "user_count": 25, "user_pending_deletion_count": 0}
    if edition is not None:
        body["edition"] = edition
    return body


def plain():
    spec = importlib.util.spec_from_file_location("duo_confirmed_licence", PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def sandboxed():
    spec = importlib.util.spec_from_file_location("restricted_sandbox_duo_licence", ROOT / "tools" / "restricted_sandbox.py")
    sandbox = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sandbox)
    return sandbox.load(PATH.read_text(), "<transformation>")["transform"]


FORBIDDEN = {"vendorErrorAsResponse": {"status": 403, "bodyContains": "Access forbidden",
                                       "body": {"stat": "FAIL", "code": 40301, "message": "Access forbidden"}}}


class DuoConfirmedLicencePurchasedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runners = {"plain": plain(), "sandbox": sandboxed()}

    def each(self, body):
        for name, run in self.runners.items():
            with self.subTest(runner=name, body=str(body)[:80]):
                yield run(body)

    def assert_not_evaluated(self, out, error_code):
        self.assertIsNone(out["transformedResponse"][KEY])
        collection = out["additionalInfo"]["dataCollection"]
        self.assertEqual(collection["status"], "error")
        self.assertEqual(collection["errorCode"], error_code)
        self.assertTrue(collection["errors"])

    def test_paid_edition_passes_with_the_trials_caveat(self):
        for edition in ["Duo Premier", "Duo Advantage", "Duo Essentials", "Duo MFA", "Duo Access",
                        "Duo Beyond", "Duo Federal MFA", "PLATFORM", "BEYOND", "ENTERPRISE"]:
            for wrapped in [summary(edition), {"response": summary(edition)},
                            {"stat": "OK", "response": summary(edition)},
                            json.dumps({"response": summary(edition)})]:
                for out in self.each(wrapped):
                    self.assertIs(out["transformedResponse"][KEY], True)
                    self.assertEqual(out["transformedResponse"]["duoEdition"], edition)
                    self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")
                    reason = out["additionalInfo"]["evaluation"]["passReasons"][0]
                    self.assertIn(edition, reason)
                    self.assertIn("edition as reported by Duo (Duo includes trials)", reason)
                    self.assertEqual(out["additionalInfo"]["evaluation"]["failReasons"], [])

    def test_free_and_trial_fail(self):
        for edition in ["Duo Free", "PERSONAL", "Duo Premier Trial", "Trial"]:
            for out in self.each({"response": summary(edition)}):
                self.assertIs(out["transformedResponse"][KEY], False)
                self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")
                self.assertTrue(out["additionalInfo"]["evaluation"]["failReasons"])
                if "rial" in edition:
                    self.assertIn("a trial", out["additionalInfo"]["evaluation"]["failReasons"][0])

    def test_forbidden_names_the_permission(self):
        for body in [FORBIDDEN, {"response": FORBIDDEN}, {"response": {"result": FORBIDDEN}}, json.dumps(FORBIDDEN)]:
            for out in self.each(body):
                self.assert_not_evaluated(out, "scope_not_granted")
                collection = out["additionalInfo"]["dataCollection"]
                self.assertEqual(collection["requiredScope"], "Grant read information")
                self.assertIn("Grant read information", collection["errors"][0])

    def test_unauthorized_is_a_reconnect_not_a_permission(self):
        body = {"vendorErrorAsResponse": {"status": 401, "body": {"stat": "FAIL", "code": 40101,
                                                                  "message": "Missing request credentials"}}}
        for out in self.each(body):
            self.assert_not_evaluated(out, "vendor_refusal")
            self.assertIn("HTTP 401", out["additionalInfo"]["dataCollection"]["errors"][0])
            self.assertNotIn("requiredScope", out["additionalInfo"]["dataCollection"])

    def test_no_edition_is_coded_not_available(self):
        for body in [summary(None), {"response": summary(None)}, {"response": summary("  ")},
                     {"response": summary(7)}]:
            for out in self.each(body):
                self.assert_not_evaluated(out, "not_available")
                self.assertTrue(out["additionalInfo"]["dataCollection"]["errors"][0]
                                .startswith("NOT-AVAILABLE: vendor exposes no licence state"))

    def test_unknown_edition_is_not_graded(self):
        for out in self.each({"response": summary("Duo Galaxy")}):
            self.assert_not_evaluated(out, "not_measured")
            self.assertEqual(out["additionalInfo"]["dataCollection"]["duoEdition"], "Duo Galaxy")

    def test_unreadable_bodies_are_not_evaluated(self):
        bad = [None, {}, "", b"", "{bad json", b"\xff\xfe", [], 42, "null", {"response": {}},
               {"stat": "FAIL", "code": 40002, "message": "Invalid request parameters"},
               {"error": "boom", "errorType": "undeclared_setting", "statusCode": 412},
               {"statusCode": 500, "body": "oops"}, "<html>502</html>",
               {"vendorErrorAsResponse": {"status": 500, "body": "x"}}]
        for body in bad:
            for out in self.each(body):
                self.assertIsNone(out["transformedResponse"][KEY])
                self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "error")


if __name__ == "__main__":
    unittest.main()
