import importlib.util
import unittest
from datetime import datetime, timedelta
from pathlib import Path


TRANSFORMATION_PATH = Path(__file__).with_name("isAntiPhishingEnabled.py")
KEY = "isAntiPhishingEnabled"


def load_transformation():
    spec = importlib.util.spec_from_file_location("abnormal_inbound_isantiphishingenabled", TRANSFORMATION_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def iso_days_ago(days):
    return (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def threat(days_ago, attack_type="Phishing: Credential", status="Auto-Remediated"):
    return {
        "threatId": "00000000-0000-0000-0000-000000000001",
        "messages": [{
            "attackType": attack_type,
            "remediationStatus": status,
            "remediationTimestamp": iso_days_ago(days_ago),
        }],
    }


class AbnormalInboundAntiPhishingWindowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = load_transformation()

    def verdict(self, body):
        return self.t.transform(body)["transformedResponse"][KEY]

    def test_window_is_90_days(self):
        self.assertEqual(self.t.WINDOW_DAYS, 90)

    def test_remediated_phishing_60_days_ago_passes(self):
        self.assertIs(self.verdict(threat(60)), True)

    def test_sent_time_fallback_60_days_ago_passes(self):
        body = {"threatId": "t", "messages": [{
            "attackType": "Social Engineering",
            "remediationStatus": "Remediated",
            "sentTime": iso_days_ago(60),
        }]}
        self.assertIs(self.verdict(body), True)

    def collection(self, body):
        return self.t.transform(body)["additionalInfo"]["dataCollection"]

    def assert_unevaluated(self, body):
        self.assertIsNone(self.verdict(body))
        dc = self.collection(body)
        self.assertEqual(dc["status"], "error")
        self.assertTrue(dc["errors"])

    # One newest threat that is neither remediated phishing nor unacted phishing proves nothing:
    # Unevaluated with the reason, never False (a tenant flipped that way on 2 Oct 2026).
    def test_remediated_phishing_100_days_ago_is_unevaluated(self):
        self.assert_unevaluated(threat(100))

    def test_any_remediated_threat_within_window_is_true(self):
        # Product decision (3 Oct 2026): a remediated threat of any type shows the inline protection is acting.
        for attack_type in ["Malware", "Spam", "Graymail", "Other"]:
            with self.subTest(attack_type):
                self.assertIs(self.verdict(threat(2, attack_type=attack_type)), True)

    def test_non_phishing_threat_not_remediated_is_unevaluated(self):
        for status in ["No Action Done", "Would Remediate", "Marked Safe", "Remediation Attempted"]:
            with self.subTest(status):
                self.assert_unevaluated(threat(2, attack_type="Spam", status=status))

    def test_old_remediated_non_phishing_threat_is_unevaluated(self):
        self.assert_unevaluated(threat(120, attack_type="Spam"))

    def test_unacted_phishing_still_fails_even_with_remediated_spam(self):
        body = threat(2, attack_type="Phishing: Credential", status="Would Remediate")
        body["messages"].append({"attackType": "Spam", "remediationStatus": "Auto-Remediated",
                                 "remediationTimestamp": iso_days_ago(1)})
        self.assertIs(self.verdict(body), False)

    def test_marked_safe_or_attempted_is_unevaluated(self):
        for status in ["Marked Safe", "Remediation Attempted"]:
            self.assert_unevaluated(threat(2, status=status))

    def test_missing_timestamps_are_unevaluated(self):
        self.assert_unevaluated({"threatId": "t", "messages": [{
            "attackType": "Phishing: Credential",
            "remediationStatus": "Auto-Remediated",
        }]})

    # A phishing-family message Abnormal saw and did not act on is a real, measured FAIL.
    def test_detect_only_status_within_window_fails(self):
        for status in ["Not Remediated", "No Action Done", "Would Remediate"]:
            self.assertIs(self.verdict(threat(5, status=status)), False, status)
            self.assertEqual(self.collection(threat(5, status=status))["status"], "success")

    def test_any_unacted_phishing_fails_even_next_to_remediated_phishing(self):
        # Master review, 3 Oct 2026: an unacted phishing message in the window fails wherever it appears.
        body = threat(3)
        body["messages"].append({"attackType": "Phishing: Credential", "remediationStatus": "No Action Done",
                                 "remediationTimestamp": iso_days_ago(3)})
        self.assertIs(self.verdict(body), False)
        body["messages"].reverse()
        self.assertIs(self.verdict(body), False)

    def test_paged_or_truncated_threat_is_unevaluated(self):
        for extra in ({"nextPageNumber": 2}, {"nextPageNumber": "2"}, {"paginationTruncated": True}, {"truncated": "true"}):
            with self.subTest(extra):
                body = threat(3)
                body.update(extra)
                self.assert_unevaluated(body)

    def test_later_page_alone_is_unevaluated(self):
        # Page 3 with no next page still leaves pages 1-2 unread.
        for extra in ({"pageNumber": 3, "nextPageNumber": None}, {"pageNumber": "2"}):
            with self.subTest(extra):
                body = threat(3)
                body.update(extra)
                self.assert_unevaluated(body)

    def test_single_or_first_page_is_scored(self):
        for extra in ({"nextPageNumber": None}, {"pageNumber": 1, "nextPageNumber": None}, {"pageNumber": "1"}, {}):
            with self.subTest(extra):
                body = threat(3)
                body.update(extra)
                self.assertIs(self.verdict(body), True)

    def test_window_is_exactly_90_days(self):
        for days, want in ((89, True), (90, True), (91, None)):
            with self.subTest(days):
                self.assertIs(self.verdict(threat(days)), want)

    def test_real_shape_threat_detail(self):
        # Shape of GET /v1/threats/{threatId} (Abnormal REST API v1): threatId plus a messages list.
        body = {"threatId": "184712ab-6d8b-47b3-89d3-a314efef79e2", "messages": [{
            "abxMessageId": 4551618356913732000, "abxPortalUrl": "https://portal.abnormalsecurity.com/home/threat-center/remediation-history/4551618356913732000",
            "subject": "Invoice overdue", "fromAddress": "billing@example.net", "toAddresses": ["ap@example.com"],
            "attackType": "Invoice/Payment Fraud (BEC)", "attackStrategy": "Name Impersonation",
            "attackVector": "Text", "attackedParty": "VIP", "impersonatedParty": "None / Others",
            "remediationStatus": "Auto-Remediated", "remediationTimestamp": iso_days_ago(1),
            "receivedTime": iso_days_ago(1), "sentTime": iso_days_ago(1), "threatId": "184712ab-6d8b-47b3-89d3-a314efef79e2",
        }]}
        self.assertIs(self.verdict(body), True)
        self.assertEqual(self.collection(body)["status"], "success")

    def test_empty_messages_list_is_unevaluated(self):
        self.assert_unevaluated({"threatId": "t", "messages": []})

    def test_empty_dict_is_unevaluated(self):
        self.assert_unevaluated({})

    def test_none_is_unevaluated(self):
        self.assert_unevaluated(None)

    def test_error_envelope_is_unevaluated(self):
        self.assert_unevaluated({"success": False, "error": "HTTP 403", "statusCode": 403})

    def test_ts_envelope_empty_is_unevaluated(self):
        self.assert_unevaluated({"data": {"threatId": "t", "messages": []}, "validation": {"status": "skipped"}})

    def test_garbage_string_is_not_evaluated(self):
        response = self.t.transform("not json")
        self.assertIsNone(response["transformedResponse"][KEY])
        self.assertTrue(response["additionalInfo"]["transformation"]["errors"])

if __name__ == "__main__":
    unittest.main()
