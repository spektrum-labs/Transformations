"""Entra isIAMLoggingEnabled: the IAM logging check writes its own key (ENG-1349).

It was wired to is_mfa_logging_enabled.py, which only writes isMFALoggingEnabled, so the IAM
logging check was never graded. isiamloggingenabled.py writes isIAMLoggingEnabled: True from
directory audit records, otherwise Not evaluated. Synthetic fixtures only.
"""
import importlib.util
import json
import unittest
from pathlib import Path

KEY = "isIAMLoggingEnabled"


def load():
    spec = importlib.util.spec_from_file_location("entra_iam_logging_eng1349",
                                                  Path(__file__).with_name("isiamloggingenabled.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


RECORD = {"id": "Directory_00000000-0000-0000-0000-000000000001", "category": "UserManagement",
          "activityDisplayName": "Update user", "activityDateTime": "2026-01-01T00:00:00Z",
          "result": "success", "loggedByService": "Core Directory"}


class IamLogging(unittest.TestCase):
    mod = load()

    def run_body(self, payload):
        out = self.mod.transform(payload)
        self.assertIn(KEY, out["transformedResponse"])
        self.assertNotIn("isMFALoggingEnabled", out["transformedResponse"])
        return out["transformedResponse"][KEY], out["additionalInfo"]["dataCollection"]["status"]

    def test_directory_audit_records_pass(self):
        self.assertEqual(self.run_body({"value": [RECORD]}), (True, "success"))

    def test_records_in_a_wrapper_and_as_a_string_pass(self):
        self.assertEqual(self.run_body({"response": {"value": [RECORD, RECORD]}}), (True, "success"))
        self.assertEqual(self.run_body(json.dumps({"value": [RECORD]})), (True, "success"))

    def test_token_service_envelope_passes(self):
        payload = {"data": {"value": [RECORD]}, "validation": {"status": "skipped", "errors": [], "warnings": []}}
        self.assertEqual(self.run_body(payload), (True, "success"))

    def test_empty_record_list_is_not_evaluated(self):
        self.assertEqual(self.run_body({"value": []}), (None, "error"))

    def test_permission_refusal_is_not_evaluated(self):
        body = {"error": {"code": "Authorization_RequestDenied", "message": "Insufficient privileges"}}
        out = self.mod.transform(body)
        self.assertIsNone(out["transformedResponse"][KEY])
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "error")
        self.assertIn("AuditLog.Read.All", out["additionalInfo"]["evaluation"]["failReasons"][0])

    def test_http_error_status_is_not_evaluated(self):
        self.assertEqual(self.run_body({"statusCode": 500, "value": [RECORD]}), (None, "error"))

    def test_missing_list_empty_and_null_bodies_are_not_evaluated(self):
        for payload in ({}, {"value": None}, {"value": "x"}, None, "", "not json", b"{}", []):
            with self.subTest(payload=payload):
                self.assertEqual(self.run_body(payload), (None, "error"))

    def test_failed_validation_is_not_evaluated(self):
        payload = {"data": {"value": [RECORD]}, "validation": {"status": "failed", "errors": ["x"], "warnings": []}}
        self.assertEqual(self.run_body(payload), (None, "error"))


if __name__ == "__main__":
    unittest.main()
