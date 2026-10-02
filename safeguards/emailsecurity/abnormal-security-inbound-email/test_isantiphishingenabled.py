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
    # Unevaluated with the reason, never False (THL Partners, 2 Oct 2026).
    def test_remediated_phishing_100_days_ago_is_unevaluated(self):
        self.assert_unevaluated(threat(100))

    def test_non_phishing_type_within_window_is_unevaluated(self):
        for attack_type in ["Malware", "Spam", "Graymail", "Other"]:
            self.assert_unevaluated(threat(2, attack_type=attack_type))

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

    def test_one_remediated_message_outweighs_an_unacted_one(self):
        body = threat(3)
        body["messages"].append({"attackType": "Phishing: Credential", "remediationStatus": "No Action Done",
                                 "remediationTimestamp": iso_days_ago(3)})
        self.assertIs(self.verdict(body), True)

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
