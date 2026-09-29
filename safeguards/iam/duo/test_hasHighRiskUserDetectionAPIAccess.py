"""hasHighRiskUserDetectionAPIAccess: Duo v2 authentication logs reachable (200 true, 403/40301 false, else null).

Shapes follow the Duo Admin API v2 authentication log example (getAuthLogs returnSpec
{"authlogs": [...], "metadata": {"next_offset": ..., "total_objects": n}}).
"""
import importlib.util
import json
import unittest
from pathlib import Path

TRANSFORMATION_PATH = Path(__file__).with_name("hasHighRiskUserDetectionAPIAccess.py")
KEY = "hasHighRiskUserDetectionAPIAccess"

ASSESSED = {
    "txid": "a", "result": "denied", "factor": "duo_push",
    "user": {"key": "DU1", "name": "narroway@example.com"},
    "adaptive_trust_assessments": {
        "more_secure_auth": {"detected_attack_detectors": ["USER_MARKED_FRAUD"], "features_version": "3.0",
                             "model_version": "2022.07.19.001", "policy_enabled": True,
                             "reason": "Low level of trust", "trust_level": "LOW"},
        "remember_me": {"features_version": "3.0", "model_version": "2022.07.19.001", "policy_enabled": False,
                        "reason": "Known Access IP", "trust_level": "NORMAL"},
    },
}
UNASSESSED = {"txid": "b", "result": "success", "factor": "duo_push", "user": {"key": "DU2", "name": "b@example.com"}}
META = {"next_offset": None, "total_objects": 2}
FORBIDDEN_BODY = {"code": 40301, "message": "Access forbidden", "stat": "FAIL"}
FORBIDDEN_MARKED = {"vendorErrorAsResponse": {"status": 403, "bodyContains": "Access forbidden",
                                              "body": FORBIDDEN_BODY}}


def load_transformation():
    spec = importlib.util.spec_from_file_location("duo_hasHighRiskUserDetectionAPIAccess", TRANSFORMATION_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DuoHighRiskUserDetectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = load_transformation()

    def run_transform(self, payload):
        return self.t.transform(payload)

    def test_200_with_risk_scored_events_is_true(self):
        out = self.run_transform({"authlogs": [ASSESSED, UNASSESSED], "metadata": META})
        tr = out["transformedResponse"]
        self.assertIs(tr[KEY], True)
        self.assertEqual(tr["riskScoredEventCount"], 1)
        self.assertEqual(tr["riskAssessedAuthPercentage"], 50.0)
        self.assertEqual(tr["lowTrustAuthCount"], 1)
        self.assertEqual(tr["riskAssessedUserCount"], 1)
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")
        self.assertEqual(out["additionalInfo"]["evaluation"]["recommendations"], [])

    def test_200_with_zero_risk_scored_events_is_true(self):
        # access = log API reachable: a 200 with no trust assessments still proves access.
        out = self.run_transform({"authlogs": [UNASSESSED, dict(UNASSESSED, txid="c")], "metadata": META})
        tr = out["transformedResponse"]
        self.assertIs(tr[KEY], True)
        self.assertEqual(tr["riskScoredEventCount"], 0)
        self.assertEqual(tr["riskAssessedAuthPercentage"], 0.0)
        self.assertEqual(out["additionalInfo"]["evaluation"]["failReasons"], [])
        self.assertIn("Risk-Based Authentication", out["additionalInfo"]["evaluation"]["recommendations"][0])
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")

    def test_assessment_without_trust_level_does_not_count(self):
        hollow = dict(UNASSESSED, adaptive_trust_assessments={"more_secure_auth": {}, "remember_me": None})
        out = self.run_transform({"authlogs": [hollow], "metadata": META})
        self.assertIs(out["transformedResponse"][KEY], True)
        self.assertEqual(out["transformedResponse"]["riskScoredEventCount"], 0)

    def test_genuine_zero_is_reachable(self):
        out = self.run_transform({"authlogs": [], "metadata": {"next_offset": None, "total_objects": 0}})
        self.assertIs(out["transformedResponse"][KEY], True)
        self.assertEqual(out["transformedResponse"]["riskScoredEventCount"], 0)
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")

    def test_wrapped_and_string_inputs(self):
        body = {"authlogs": [ASSESSED], "metadata": META}
        for payload in (json.dumps(body), {"apiResponse": body},
                        {"data": body, "validation": {"status": "valid", "errors": [], "warnings": []}}):
            with self.subTest(payload=str(payload)[:40]):
                self.assertIs(self.run_transform(payload)["transformedResponse"][KEY], True)

    def test_no_evidence_is_null(self):
        # empty, None, other errors (401/429/500 bodies) and unrelated bodies: null, not judged.
        for payload in (None, {}, [], "", "{}", "not json", {"authlogs": [], "metadata": {}},
                        {"error": "Unauthorized", "code": 401},
                        {"stat": "FAIL", "code": 42901, "message": "Too Many Requests"},
                        {"stat": "FAIL", "code": 50000, "message": "Internal Server Error"},
                        {"stat": "FAIL", "code": 40301},
                        {"users": [{"user_id": "DU3"}], "metadata": META},
                        {"authlogs": "not a list", "metadata": META}):
            with self.subTest(payload=payload):
                out = self.run_transform(payload)
                self.assertIsNone(out["transformedResponse"][KEY])
                self.assertIsNone(out["transformedResponse"]["riskScoredEventCount"])
                self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "error")
                self.assertEqual(out["additionalInfo"]["evaluation"]["failReasons"], [])
                self.assertEqual(out["additionalInfo"]["evaluation"]["passReasons"], [])

    # --- Integration-Service vendorErrorAsResponse marker (getAuthLogs opt-in) ---
    def test_access_forbidden_is_a_measured_fail(self):
        body_as_string = {"vendorErrorAsResponse": dict(FORBIDDEN_MARKED["vendorErrorAsResponse"],
                                                        body=json.dumps(FORBIDDEN_BODY))}
        for payload in (FORBIDDEN_MARKED, json.dumps(FORBIDDEN_MARKED), body_as_string,
                        {"apiResponse": FORBIDDEN_MARKED},
                        {"data": FORBIDDEN_MARKED, "validation": {"status": "valid", "errors": [], "warnings": []}}):
            with self.subTest(payload=str(payload)[:60]):
                out = self.run_transform(payload)
                info = out["additionalInfo"]
                self.assertIs(out["transformedResponse"][KEY], False)
                self.assertIsNone(out["transformedResponse"]["riskScoredEventCount"])
                self.assertEqual(info["dataCollection"]["status"], "success")
                self.assertIn("admin API key lacks Grant read log permission", info["evaluation"]["failReasons"][0])
                self.assertIn("Grant read log", info["evaluation"]["recommendations"][0])

    def test_other_marker_stays_not_evaluated(self):
        for marker in ({"status": 403, "bodyContains": "Access forbidden", "body": {"code": 40300, "message": "Access forbidden"}},
                       {"status": 401, "bodyContains": "Access forbidden", "body": FORBIDDEN_BODY},
                       {"status": 403, "bodyContains": "Access forbidden", "body": "Access forbidden"},
                       {"status": 429, "bodyContains": "Too Many Requests",
                        "body": {"code": 42901, "message": "Too Many Requests", "stat": "FAIL"}},
                       {"status": 500, "bodyContains": "Internal Server Error", "body": "Internal Server Error"},
                       None):
            with self.subTest(marker=str(marker)[:60]):
                out = self.run_transform({"vendorErrorAsResponse": marker})
                self.assertIsNone(out["transformedResponse"][KEY])
                self.assertIsNone(out["transformedResponse"]["riskScoredEventCount"])
                self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "error")
                self.assertEqual(out["additionalInfo"]["evaluation"]["failReasons"], [])


if __name__ == "__main__":
    unittest.main()
