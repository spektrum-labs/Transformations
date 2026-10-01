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


if __name__ == "__main__":
    unittest.main()
