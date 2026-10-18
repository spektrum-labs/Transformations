"""A quiet Proofpoint tenant reads Not evaluated WITH a reason code, not as an unexplained error.

A report window with no traffic (no phishing detections, no URL-bearing messages, no
attachment-bearing messages) cannot prove or disprove the control, so the answer is None.
Token-Service grades a None as FAILED unless additionalInfo.dataCollection.status is "error",
so the status stays "error". What was missing is a machine-readable reason: the status reads as
an error with prose only, and the readiness stream reports an unexplained failure (UNKNOWN).

These tests pin three things: the value stays None, the status stays "error" (the contract in
tools/check_none_not_evaluated.py), and the same output now carries the reason code "no_volume"
in dataCollection.errorCode and beside the criterion as reasonCode. Measured answers and real
errors (a 403 body, a crash) carry no such code. Synthetic data only.
"""
import importlib.util
import os
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name):
    spec = importlib.util.spec_from_file_location("pptp_novol_" + name, os.path.join(HERE, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Poisoned(dict):
    """A non-empty object whose every read raises, to drive the transform's except path."""

    def __init__(self):
        super().__init__(poisoned=True)

    def boom(self, *args, **kwargs):
        raise RuntimeError("poisoned read")

    get = __getitem__ = __contains__ = keys = items = values = __iter__ = boom

    def __len__(self):
        return 1


KEYS = {
    "isantiphishingenabled": "isAntiPhishingEnabled",
    "issafelinksenabled": "isSafeLinksEnabled",
    "issafeattachmentsenabled": "isSafeAttachmentsEnabled",
}

# A valid report with nothing to measure in the window.
QUIET = {
    "isantiphishingenabled": [
        {"threatCategories": [], "totalVolume": 0},
        {"threatCategories": [{"name": "phishing", "volume": 0}, {"name": "bec", "volume": 0}], "totalVolume": 0},
    ],
    "issafelinksenabled": [
        {"statsByBreakdownValue": [{"breakdownName": "url", "breakdownMessagesTotal": 0}]},
    ],
    "issafeattachmentsenabled": [
        {"statsByBreakdownValue": [{"breakdownName": "attachment", "breakdownMessagesTotal": 0}]},
    ],
}

# Answers that are not "no volume": an error body, text, nothing, a crash.
NOT_QUIET = [{"error": "403 Forbidden"}, {"errors": ["rate limited"]}, "not json {", None, Poisoned()]


class NoVolumeCarriesAReasonCode(unittest.TestCase):
    def test_a_quiet_window_is_none_with_status_error_and_the_no_volume_code(self):
        for name, key in KEYS.items():
            for body in QUIET[name]:
                with self.subTest(transform=name, body=repr(body)[:70]):
                    out = load(name).transform(body)
                    self.assertIsNone(out["transformedResponse"][key])
                    collection = out["additionalInfo"]["dataCollection"]
                    self.assertEqual(collection["status"], "error")
                    self.assertTrue(collection["errors"])
                    self.assertEqual(collection["errorCode"], "no_volume")
                    self.assertEqual(out["transformedResponse"]["reasonCode"], "no_volume")

    def test_the_prose_reason_is_kept(self):
        for name, key in KEYS.items():
            with self.subTest(transform=name):
                out = load(name).transform(QUIET[name][0])
                reasons = out["additionalInfo"]["evaluation"]["failReasons"]
                self.assertTrue(reasons)
                self.assertEqual(out["additionalInfo"]["dataCollection"]["errors"], reasons)

    def test_a_real_error_or_crash_is_not_labelled_no_volume(self):
        for name, key in KEYS.items():
            for body in NOT_QUIET:
                with self.subTest(transform=name, body=repr(body)[:60]):
                    out = load(name).transform(body)
                    self.assertIsNone(out["transformedResponse"][key])
                    self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "error")
                    self.assertNotEqual(out["additionalInfo"]["dataCollection"].get("errorCode"), "no_volume")
                    self.assertNotIn("reasonCode", out["transformedResponse"])

    def test_a_measured_answer_carries_no_code(self):
        measured = {
            "isantiphishingenabled": {"threatCategories": [{"name": "phishing", "volume": 3}], "totalVolume": 3},
            "issafelinksenabled": {"statsByBreakdownValue": [
                {"breakdownName": "url", "breakdownMessagesTotal": 100, "messagesWithNonRewrittenUrls": 1}]},
            "issafeattachmentsenabled": {"statsByBreakdownValue": [
                {"breakdownName": "attachment", "breakdownMessagesTotal": 100, "breakdownProtectedMessagesTotal": 99}]},
        }
        for name, key in KEYS.items():
            with self.subTest(transform=name):
                out = load(name).transform(measured[name])
                self.assertIs(out["transformedResponse"][key], True)
                collection = out["additionalInfo"]["dataCollection"]
                self.assertEqual(collection["status"], "success")
                self.assertNotIn("errorCode", collection)
                self.assertNotIn("reasonCode", out["transformedResponse"])

    def test_a_below_threshold_answer_is_still_false_without_a_code(self):
        out = load("issafelinksenabled").transform({"statsByBreakdownValue": [
            {"breakdownName": "url", "breakdownMessagesTotal": 100, "messagesWithNonRewrittenUrls": 50}]})
        self.assertIs(out["transformedResponse"]["isSafeLinksEnabled"], False)
        self.assertNotIn("errorCode", out["additionalInfo"]["dataCollection"])


if __name__ == "__main__":
    unittest.main()
