import importlib.util
import unittest
from pathlib import Path


TRANSFORMATION_PATH = Path(__file__).with_name("nuclei_transform.py")


def load_transformation():
    spec = importlib.util.spec_from_file_location("nuclei_transform", TRANSFORMATION_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def scan(**overrides):
    # Shape of a real multi-domain scan (values arrive as strings).
    body = {
        "status": "success",
        "primaryDomain": "example.com",
        "findings": [],
        "total": "0",
        "domainsScanned": "2",
        "totalDiscovered": "2",
        "domainResults": [
            {"domain": "example.com", "findingsCount": 0, "status": "success"},
            {"domain": "www.example.com", "findingsCount": 0, "status": "success"},
        ],
        "errors": [],
    }
    body.update(overrides)
    return body


def verdict(payload):
    return load_transformation().transform(payload)["transformedResponse"]


class NucleiTransformTest(unittest.TestCase):
    def test_clean_scan_passes(self):
        self.assertEqual(verdict(scan()), {**verdict(scan()), "noCriticalFindings": True, "noHighFindings": True})
        self.assertEqual(verdict(scan())["domain"], "example.com")

    def test_zero_domains_scanned_fails(self):
        v = verdict(scan(domainsScanned="0", domainResults=[]))
        self.assertFalse(v["noCriticalFindings"])
        self.assertFalse(v["noHighFindings"])

    def test_a_failed_domain_fails(self):
        results = [{"domain": "example.com", "findingsCount": 0, "status": "success"},
                   {"domain": "www.example.com", "findingsCount": 0, "status": "error"}]
        v = verdict(scan(domainResults=results))
        self.assertFalse(v["noCriticalFindings"])
        self.assertFalse(v["noHighFindings"])

    def test_an_unresponsive_domain_is_not_a_failure(self):
        results = [{"domain": "example.com", "findingsCount": 0, "status": "success"},
                   {"domain": "dead.example.com", "findingsCount": 0, "status": "unresponsive"}]
        v = verdict(scan(domainResults=results, domainsUnresponsive=1, domainsResponsive=1))
        self.assertTrue(v["noCriticalFindings"])
        self.assertTrue(v["noHighFindings"])

    def test_all_unresponsive_fails_closed(self):
        v = verdict({"status": "error", "message": "No host was scanned: of 2 domain(s), 2 unresponsive"})
        self.assertFalse(v["noCriticalFindings"])
        self.assertFalse(v["noHighFindings"])

    def test_scan_errors_fail(self):
        v = verdict(scan(errors=[{"domain": "www.example.com", "error": "timeout"}]))
        self.assertFalse(v["noCriticalFindings"])

    def test_critical_finding_fails_only_critical(self):
        v = verdict(scan(findings=[{"info": {"severity": "critical", "name": "CVE-X"}}]))
        self.assertFalse(v["noCriticalFindings"])
        self.assertTrue(v["noHighFindings"])

    def test_single_domain_shape_still_works(self):
        v = verdict({"status": "success", "domain": "a.com", "findings": [], "total": 0})
        self.assertTrue(v["noCriticalFindings"])

    # Partial (capped) scans, 2 Oct 2026. Shapes follow the recorded inputSummary of the live scans.
    def full(self, payload):
        return load_transformation().transform(payload)

    def test_carlex_capped_clean_scan_is_unevaluated(self):
        # Carlex 2 Oct 01:04 ET: 25 of 45 discovered hosts scanned, 0 findings. Was a pass.
        out = self.full(scan(primaryDomain="carlex.com", domainsScanned="25", totalDiscovered="45", domainsCapped="True",
                             templatesScanned="1675", domainResults=[]))
        tr, info = out["transformedResponse"], out["additionalInfo"]
        self.assertIsNone(tr["noCriticalFindings"])
        self.assertIsNone(tr["noHighFindings"])
        self.assertEqual(info["dataCollection"]["status"], "error")
        self.assertIn("Only 25 of 45 discovered host(s) of carlex.com were scanned", info["dataCollection"]["errors"][0])
        self.assertIn("not a clean estate", info["dataCollection"]["errors"][0])
        self.assertEqual(info["transformation"]["inputSummary"]["totalDiscovered"], 45)

    def test_numeric_cap_without_flag_is_unevaluated(self):
        out = self.full(scan(domainsScanned="25", totalDiscovered="70", domainResults=[]))
        self.assertIsNone(out["transformedResponse"]["noCriticalFindings"])
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "error")

    def test_see_to_solve_full_clean_scan_still_passes(self):
        # See to Solve 2 Oct 01:04 ET: 20 of 20 hosts, 0 findings: a real pass.
        out = self.full(scan(primaryDomain="seetosolve.com", domainsScanned="20", totalDiscovered="20", domainsCapped="False",
                             domainResults=[]))
        tr, info = out["transformedResponse"], out["additionalInfo"]
        self.assertTrue(tr["noCriticalFindings"])
        self.assertTrue(tr["noHighFindings"])
        self.assertEqual(info["dataCollection"]["status"], "success")

    def test_finding_on_a_partial_scan_still_fails(self):
        out = self.full(scan(domainsScanned="25", totalDiscovered="45", domainsCapped="True", domainResults=[], total="1",
                             findings=[{"info": {"severity": "critical", "name": "CVE-2024-0001"}}]))
        tr, info = out["transformedResponse"], out["additionalInfo"]
        self.assertFalse(tr["noCriticalFindings"])
        self.assertEqual(info["dataCollection"]["status"], "success")
        self.assertTrue(any("Only 25 of 45" in r for r in info["evaluation"]["failReasons"]))

    def test_high_finding_on_a_partial_high_scan_fails(self):
        out = self.full(scan(domainsScanned="25", totalDiscovered="41", domainsCapped="True", domainResults=[], total="1",
                             findings=[{"info": {"severity": "high", "name": "Exposed panel"}}]))
        self.assertFalse(out["transformedResponse"]["noHighFindings"])
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")

    def test_medium_only_on_a_partial_scan_is_unevaluated(self):
        out = self.full(scan(domainsScanned="25", totalDiscovered="45", domainsCapped="True", domainResults=[], total="1",
                             findings=[{"info": {"severity": "medium", "name": "Header missing"}}]))
        self.assertIsNone(out["transformedResponse"]["noCriticalFindings"])
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "error")

    def test_capped_flag_false_with_equal_counts_passes(self):
        self.assertTrue(verdict(scan(domainsCapped="false"))["noCriticalFindings"])

    def test_unparseable_counts_do_not_cap(self):
        # Unparseable coverage cannot prove a partial scan; the existing guards still apply.
        self.assertTrue(verdict(scan(domainsScanned="2", totalDiscovered="n/a"))["noCriticalFindings"])


if __name__ == "__main__":
    unittest.main()
