"""Abnormal confirmedLicensePurchased. Synthetic data only."""
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
    "{not json",
    {"hello": "world"},
    {"foo": {"bar": [1, 2, 3]}},
    {"statusCode": 401, "error": "Unauthorized"},
    {"statusCode": 403, "error": "Forbidden"},
    {"error": {"type": "authentication_error", "message": "invalid credentials"}},
    {"detail": "token revoked"},
    {"threats": "None"},
    {"threats": None},
    {"status": "success", "status_code": 200, "data": {"session_settings": {"inactivity_timeout_minutes": 60}}},
    {"data": {"statusCode": 403, "error": "Forbidden"}, "validation": {"status": "passed"}},
]

THREATS = {"threats": [{"threatId": "t-1", "subject": "x"}], "pageNumber": 1, "nextPageNumber": 2, "total": 1}


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

    def run_t(self, body):
        return self.t.transform(body)

    def v(self, body):
        return self.run_t(body)["transformedResponse"]["confirmedLicensePurchased"]

    def test_threats_list_passes(self):
        self.assertIs(self.v(THREATS), True)

    def test_empty_threats_list_still_passes(self):
        self.assertIs(self.v({"threats": [], "pageNumber": 1}), True)

    def test_json_string_and_wrapped_forms_pass(self):
        self.assertIs(self.v(json.dumps(THREATS)), True)
        self.assertIs(self.v({"apiResponse": THREATS}), True)
        self.assertIs(self.v(stringify(THREATS)), True)

    def test_enriched_input_is_unwrapped(self):
        enriched = {"data": {"apiResponse": THREATS}, "validation": {"status": "passed", "errors": [], "warnings": []}}
        self.assertIs(self.v(enriched), True)

    def test_no_evidence_is_not_evaluated(self):
        for body in NO_EVIDENCE:
            with self.subTest(body=body):
                out = self.run_t(body)
                self.assertIsNone(out["transformedResponse"]["confirmedLicensePurchased"])
                dc = out["additionalInfo"]["dataCollection"]
                self.assertEqual(dc["status"], "error")
                self.assertTrue(dc["errors"])

    def test_pass_has_clean_data_collection(self):
        dc = self.run_t(THREATS)["additionalInfo"]["dataCollection"]
        self.assertEqual(dc["status"], "success")

    def test_never_false(self):
        for body in NO_EVIDENCE + [THREATS]:
            self.assertIsNot(self.v(body), False)


if __name__ == "__main__":
    unittest.main()
