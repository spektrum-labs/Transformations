"""isDNSLoggingEnabled must read DNSFilter's real total_requests report.

[dd-watch] 2026-10-27: every prod DNSFilter customer failed this criterion. The Integration-Service
definition called a traffic report that does not exist, and this transform looked for keys
(total_queries, queries, logging_enabled) that /v1/traffic_reports/total_requests never returns. The
vendor answers {"data": {"organization_ids": [...], "values": [{"bucket": ..., "total": N, ...}]}}
with one bucket per day (bucket_size auto) over the requested window. DNSFilter has no logging on/off
switch and keeps query logs for 9 days, so the measured fact is "the organisation produced DNS traffic
in the window": the sum of data.values[].total.
"""
import importlib.util
import json
import unittest
from pathlib import Path

try:
    from pydantic import BaseModel
except ImportError:  # the schema check is skipped where pydantic is absent, as the local tester does
    BaseModel = None

HERE = Path(__file__).resolve().parent


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def bucket(day, total, **extra):
    """One TrafficReportsTotalRequestsResult bucket, every field the vendor documents."""
    row = {"network_id": None, "network_name": None, "bucket": f"2026-10-{day:02d}T00:00:00Z",
           "policies": [], "policies_names": [], "scheduled_policies": [], "scheduled_policies_names": [],
           "total": total, "total_networks": total, "total_proxies": 0, "total_agents": 0}
    row.update(extra)
    return row


def report(*totals):
    """The report as Token-Service hands it over: codeexecutor._parse_api_response_for_transformer has
    already stripped the vendor's top-level `data` wrapper (it navigates response/result/apiResponse/
    Output/data), so the TrafficReportsTotalRequests fields sit at the top level."""
    return {"organization_ids": [4242], "organization_names": ["Example Org"],
            "network_ids": [], "network_names": [],
            "values": [bucket(20 + i, t) for i, t in enumerate(totals)]}


def total_requests(*totals):
    """The raw GET /v1/traffic_reports/total_requests body, `data` wrapper and all."""
    return {"data": report(*totals)}


def enriched(data, status="passed"):
    """The input shape Token-Service hands a transform once the schema has been checked."""
    return {"data": data, "validation": {"status": status, "errors": [], "warnings": []}}


class IsDnsLoggingEnabledTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = load(HERE / "isdnsloggingenabled.py", "dnsfilter_isdnsloggingenabled")

    def verdict(self, out):
        return out["transformedResponse"]["isDNSLoggingEnabled"]

    # 1. Happy path: the report as the pipeline delivers it, with traffic in the window.
    def test_traffic_in_the_window_proves_logging(self):
        out = self.t.transform(enriched(report(1200, 980, 0, 1534, 1101, 1300, 1422, 311)))
        self.assertTrue(self.verdict(out))
        self.assertEqual(out["transformedResponse"]["totalQueries"], 7848)
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")
        self.assertEqual(out["additionalInfo"]["evaluation"]["failReasons"], [])
        self.assertEqual(len(out["additionalInfo"]["evaluation"]["passReasons"]), 1)
        self.assertIn("7848", out["additionalInfo"]["evaluation"]["passReasons"][0])

    def test_the_raw_vendor_body_with_its_data_wrapper_is_read_the_same_way(self):
        out = self.t.transform(enriched(total_requests(1200, 980, 0)))
        self.assertTrue(self.verdict(out))
        self.assertEqual(out["transformedResponse"]["totalQueries"], 2180)

    def test_the_legacy_unenriched_string_body_is_read_the_same_way(self):
        out = self.t.transform(json.dumps(report(5, 0, 9)))
        self.assertTrue(self.verdict(out))
        self.assertEqual(out["transformedResponse"]["totalQueries"], 14)

    def test_a_response_wrapper_is_unwrapped_first(self):
        out = self.t.transform({"response": total_requests(3)})
        self.assertTrue(self.verdict(out))
        self.assertEqual(out["transformedResponse"]["totalQueries"], 3)

    # 2. Failure: a report with buckets but no traffic at all.
    def test_a_window_with_no_traffic_fails(self):
        out = self.t.transform(enriched(report(0, 0, 0, 0, 0, 0, 0, 0)))
        self.assertIs(self.verdict(out), False)
        self.assertEqual(out["transformedResponse"]["totalQueries"], 0)
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")
        self.assertTrue(out["additionalInfo"]["evaluation"]["failReasons"])
        self.assertTrue(out["additionalInfo"]["evaluation"]["recommendations"])

    def test_an_empty_values_list_fails(self):
        out = self.t.transform(enriched({"organization_ids": [1], "values": []}))
        self.assertIs(self.verdict(out), False)
        self.assertEqual(out["transformedResponse"]["totalQueries"], 0)

    def test_the_vendor_is_not_believed_about_sub_totals_only(self):
        """Only `total` counts; a bucket whose `total` is missing or null adds nothing."""
        body = report(10, 4)
        body["values"].append(bucket(28, None, total_networks=99))
        del body["values"][1]["total"]
        out = self.t.transform(enriched(body))
        self.assertTrue(self.verdict(out))
        self.assertEqual(out["transformedResponse"]["totalQueries"], 10)

    # 3-5. Bodies that prove nothing are not measured.
    def not_measured(self, out):
        self.assertIsNone(self.verdict(out))
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "error")
        self.assertTrue(out["additionalInfo"]["dataCollection"]["errors"])
        self.assertEqual(out["additionalInfo"]["evaluation"]["passReasons"], [])

    def test_empty_bodies_are_not_measured(self):
        for body in ({}, "{}", None, {"data": {}}, {"data": None}, {"organization_ids": [1]}):
            with self.subTest(body=body):
                self.not_measured(self.t.transform(body))

    def test_an_error_envelope_is_not_measured(self):
        for body in ({"error": "Not Authorized"}, {"status_code": 404, "error": "Not Found"},
                     {"errors": [{"detail": "Record not found"}]}):
            with self.subTest(body=body):
                self.not_measured(self.t.transform(body))

    def test_an_unrelated_payload_is_not_measured(self):
        for body in ({"hello": "world"}, {"foo": {"bar": [1, 2, 3]}}, {"data": [{"id": 1}, {"id": 2}]},
                     {"data": {"values": "many"}}, {"values": "many"}, {"values": {"total": 5}}):
            with self.subTest(body=body):
                self.not_measured(self.t.transform(body))

    def test_failed_validation_is_not_measured(self):
        out = self.t.transform(enriched({"hello": "world"}, status="failed"))
        self.not_measured(out)

    # 6. Malformed input.
    def test_malformed_json_is_not_measured(self):
        out = self.t.transform("{not json")
        self.assertIsNone(self.verdict(out))
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "error")
        self.assertTrue(out["additionalInfo"]["transformation"]["errors"])

    def test_the_output_contract_is_unchanged(self):
        out = self.t.transform(enriched(report(7)))
        self.assertEqual(set(out["transformedResponse"]), {"isDNSLoggingEnabled", "totalQueries"})
        meta = out["additionalInfo"]["metadata"]
        self.assertEqual(meta["transformationId"], "isDNSLoggingEnabled")
        self.assertEqual(meta["vendor"], "DNSFilter")

    @unittest.skipIf(BaseModel is None, "pydantic not installed")
    def test_the_schema_accepts_the_report_in_both_shapes(self):
        """Token-Service validates the (already unwrapped) body against schemas/isdnsloggingenabled.py
        before calling transform; the old schema typed `data` as a list, so a raw body was rejected and
        the criterion never ran."""
        schema = load(HERE / "schemas" / "isdnsloggingenabled.py", "dnsfilter_isdnsloggingenabled_schema")
        unwrapped = schema.IsdnsloggingenabledInput.model_validate(report(12, 0, 3)).model_dump()
        self.assertEqual(sum(v["total"] for v in unwrapped["values"]), 15)
        raw = schema.IsdnsloggingenabledInput.model_validate(total_requests(12, 0, 3)).model_dump()
        self.assertEqual(sum(v["total"] for v in raw["data"]["values"]), 15)
        schema.IsdnsloggingenabledInput.model_validate({"error": "Not Authorized"})


if __name__ == "__main__":
    unittest.main()
