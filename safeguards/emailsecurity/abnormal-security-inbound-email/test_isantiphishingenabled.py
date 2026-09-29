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

    def test_remediated_phishing_100_days_ago_fails(self):
        self.assertIs(self.verdict(threat(100)), False)

    def test_sent_time_fallback_60_days_ago_passes(self):
        body = {"threatId": "t", "messages": [{
            "attackType": "Social Engineering",
            "remediationStatus": "Remediated",
            "sentTime": iso_days_ago(60),
        }]}
        self.assertIs(self.verdict(body), True)

    def test_detect_only_status_within_window_fails(self):
        self.assertIs(self.verdict(threat(60, status="Not Remediated")), False)

    def test_non_phishing_type_within_window_fails(self):
        self.assertIs(self.verdict(threat(60, attack_type="Malware")), False)

    def test_missing_timestamps_fail(self):
        body = {"threatId": "t", "messages": [{
            "attackType": "Phishing: Credential",
            "remediationStatus": "Auto-Remediated",
        }]}
        self.assertIs(self.verdict(body), False)

    def test_empty_messages_list_fails(self):
        self.assertIs(self.verdict({"threatId": "t", "messages": []}), False)

    def test_empty_dict_fails(self):
        self.assertIs(self.verdict({}), False)

    def test_none_fails(self):
        self.assertIs(self.verdict(None), False)

    def test_error_envelope_fails(self):
        body = {"success": False, "error": "HTTP 403", "statusCode": 403}
        self.assertIs(self.verdict(body), False)

    def test_garbage_string_fails(self):
        response = self.t.transform("not json")
        self.assertIs(response["transformedResponse"][KEY], False)
        self.assertTrue(response["additionalInfo"]["transformation"]["errors"])


if __name__ == "__main__":
    unittest.main()
