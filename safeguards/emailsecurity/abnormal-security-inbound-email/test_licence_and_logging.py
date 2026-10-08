"""Abnormal confirmedLicensePurchased and isEmailLoggingEnabled. Synthetic data only."""
import importlib.util
import json
import unittest
from pathlib import Path

HERE = Path(__file__).parent


def load(name):
    spec = importlib.util.spec_from_file_location("abnormal_inbound_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


NO_EVIDENCE = [
    {},
    None,
    "{}",
    {"hello": "world"},
    {"foo": {"bar": [1, 2, 3]}},
    {"statusCode": 401, "error": "Unauthorized"},
    {"statusCode": 403, "error": "Forbidden"},
    {"error": {"type": "authentication_error", "message": "invalid credentials"}},
    {"detail": "token revoked"},
    {"status": "success", "status_code": 200, "data": {"session_settings": {"inactivity_timeout_minutes": 60}}},
]

THREATS = {"threats": [{"threatId": "t-1", "subject": "x"}], "pageNumber": 1, "nextPageNumber": 2, "total": 1}
AUDIT = {
    "auditLogs": [{
        "action": "login", "category": "", "status": "SUCCESS", "sourceIp": "203.0.113.5",
        "tenantName": "example", "timestamp": "2026-10-08 15:47:47.922000+00:00", "user": {"email": "a@example.test"},
    }],
    "pageNumber": 1,
}


def stringify(x):
    """Token-Service stores every leaf as a string; replays see this shape."""
    if isinstance(x, dict):
        return {k: stringify(v) for k, v in x.items()}
    if isinstance(x, list):
        return [stringify(v) for v in x]
    return str(x)


class LicenseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = load("confirmedLicensePurchased")

    def v(self, body):
        return self.t.transform(body)["transformedResponse"]["confirmedLicensePurchased"]

    def test_threats_list_passes(self):
        self.assertIs(self.v(THREATS), True)

    def test_empty_threats_list_still_passes(self):
        self.assertIs(self.v({"threats": [], "pageNumber": 1}), True)

    def test_json_string_and_wrapped_forms_pass(self):
        self.assertIs(self.v(json.dumps(THREATS)), True)
        self.assertIs(self.v({"apiResponse": THREATS}), True)
        self.assertIs(self.v(stringify(THREATS)), True)

    def test_no_evidence_fails(self):
        for body in NO_EVIDENCE:
            with self.subTest(body=body):
                self.assertIs(self.v(body), False)

    def test_threats_not_a_list_fails(self):
        self.assertIs(self.v({"threats": "None"}), False)
        self.assertIs(self.v({"threats": None}), False)

    def test_malformed_json_fails(self):
        self.assertIs(self.v("{not json"), False)


class LoggingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = load("isEmailLoggingEnabled")

    def v(self, body):
        return self.t.transform(body)["transformedResponse"]["isEmailLoggingEnabled"]

    def test_audit_records_pass(self):
        self.assertIs(self.v(AUDIT), True)

    def test_json_string_wrapped_and_stringified_forms_pass(self):
        self.assertIs(self.v(json.dumps(AUDIT)), True)
        self.assertIs(self.v({"response": AUDIT}), True)
        self.assertIs(self.v(stringify(AUDIT)), True)

    def test_empty_list_is_not_evaluated(self):
        out = self.t.transform({"auditLogs": [], "pageNumber": 1})
        self.assertIsNone(out["transformedResponse"]["isEmailLoggingEnabled"])
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "error")
        out = self.t.transform(json.dumps({"auditLogs": []}))
        self.assertIsNone(out["transformedResponse"]["isEmailLoggingEnabled"])

    def test_licence_note_in_pass_reason(self):
        lic = load("confirmedLicensePurchased").transform(THREATS)
        self.assertIn("tier not visible", lic["additionalInfo"]["evaluation"]["passReasons"][0])

    def test_records_without_timestamp_fail(self):
        self.assertIs(self.v({"auditLogs": [{"action": "login"}, "x", None]}), False)

    def test_no_evidence_fails(self):
        for body in NO_EVIDENCE:
            with self.subTest(body=body):
                self.assertIs(self.v(body), False)

    def test_null_or_stringified_null_timestamp_fails(self):
        for stamp in (None, "", "None", "null"):
            with self.subTest(stamp=stamp):
                self.assertIs(self.v({"auditLogs": [{"action": "login", "timestamp": stamp}]}), False)

    def test_threat_list_is_not_audit_evidence(self):
        self.assertIs(self.v(THREATS), False)

    def test_malformed_json_fails(self):
        self.assertIs(self.v("{not json"), False)


if __name__ == "__main__":
    unittest.main()
