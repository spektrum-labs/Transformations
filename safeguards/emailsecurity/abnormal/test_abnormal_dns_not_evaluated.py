"""Abnormal isDNSConfigured: a DNS-helper outage is Not evaluated, never failed. Synthetic data only."""
import importlib.util
import unittest
from pathlib import Path

HERE = Path(__file__).parent
spec = importlib.util.spec_from_file_location("abnormal_isdnsconfigured", HERE / "isdnsconfigured.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

KEYS = ("isDNSConfigured", "isDMARCConfigured", "isDKIMConfigured", "isSPFConfigured")
OUTAGE = [
    {},
    None,
    "",
    "{not json",
    {"hello": "world"},
    {"statusCode": 503, "error": "dns_unavailable"},
    {"error": {"type": "dns_unavailable", "message": "resolver down"}},
    {"result": {}},
    {"data": {"statusCode": 503, "error": "dns_unavailable"}, "validation": {"status": "passed"}},
]


class DnsTests(unittest.TestCase):
    def test_all_records_pass(self):
        out = mod.transform({"result": {"SPF": "v=spf1 -all", "DKIM": True, "DMARC": "v=DMARC1; p=reject"}})
        r = out["transformedResponse"]
        self.assertTrue(all(r[k] is True for k in KEYS))
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")

    def test_missing_record_is_a_real_fail(self):
        r = mod.transform({"result": {"SPF": "v=spf1 -all", "DKIM": False, "DMARC": "v=DMARC1"}})["transformedResponse"]
        self.assertIs(r["isDNSConfigured"], False)
        self.assertIs(r["isDKIMConfigured"], False)
        self.assertIs(r["isSPFConfigured"], True)

    def test_all_false_valid_domain_response_is_a_real_fail(self):
        r = mod.transform({"result": {"SPF": False, "DKIM": False, "DMARC": False}})["transformedResponse"]
        self.assertTrue(all(r[k] is False for k in KEYS))

    def test_outage_is_not_evaluated(self):
        for body in OUTAGE:
            with self.subTest(body=body):
                out = mod.transform(body)
                for k in KEYS:
                    self.assertIsNone(out["transformedResponse"][k])
                dc = out["additionalInfo"]["dataCollection"]
                self.assertEqual(dc["status"], "error")
                self.assertTrue(dc["errors"])

    def test_enriched_input_is_unwrapped(self):
        body = {"data": {"result": {"SPF": True, "DKIM": True, "DMARC": True}}, "validation": {"status": "passed"}}
        self.assertIs(mod.transform(body)["transformedResponse"]["isDNSConfigured"], True)


if __name__ == "__main__":
    unittest.main()
