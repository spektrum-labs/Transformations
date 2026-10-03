import importlib.util
import unittest
from datetime import datetime, timedelta
from pathlib import Path

HERE = Path(__file__).parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def scan(**overrides):
    # Shape of runParallelASMScan (IS src/models/integrations/asm/nuclei.py); counts arrive as strings.
    body = {
        "status": "success",
        "primaryDomain": "example.com",
        "findings": [],
        "total": "0",
        "domainsScanned": "2",
        "totalDiscovered": "3",
        "domainsCapped": False,
        "domainResults": [
            {"domain": "example.com", "findingsCount": 0, "status": "success"},
            {"domain": "www.example.com", "findingsCount": 0, "status": "success"},
        ],
        "templatesScanned": "120",
        "errors": [],
        "timestamp": datetime.utcnow().isoformat(),
    }
    body.update(overrides)
    if "findings" in overrides and "total" not in overrides:
        body["total"] = str(len(body["findings"]) if isinstance(body["findings"], list) else 0)
    return body


CRIT_KEV = {"template-id": "CVE-2023-1", "info": {"name": "CVE-2023-1", "severity": "critical", "tags": ["cve", "kev"]}}
CRIT = {"template-id": "CVE-2023-2", "info": {"name": "CVE-2023-2", "severity": "critical", "tags": "cve,rce"}}

FAILED_SCANS = [
    {},
    None,
    "not json",
    {"status": "error", "message": "Lambda HTTP 429: Rate Exceeded"},
    scan(domainsScanned="0", domainResults=[]),
    scan(errors=[{"domain": "www.example.com", "error": "timeout"}]),
    scan(domainResults=[{"domain": "example.com", "findingsCount": 0, "status": "error"}]),
    {"status": "success", "domain": "a.com", "findings": [], "total": 0},  # single-domain fallback: no discovery
    # IS #1307: every host unreachable fails closed as status error.
    {"status": "error", "message": "No host was scanned: of 2 domain(s), 2 unresponsive and the rest errored"},
]

# IS #1307: a host that drops every connection is reported as unresponsive, not as a failed scan.
ONE_UNRESPONSIVE = dict(
    domainResults=[
        {"domain": "example.com", "findingsCount": 0, "status": "success"},
        {"domain": "dead.example.com", "findingsCount": 0, "status": "unresponsive"},
    ],
    domainsUnresponsive=1,
    domainsResponsive=1,
)

KEYS = {
    "isasmenabled": ("isASMEnabled", False),
    "externalassetinventorycount": ("externalAssetInventoryCount", None),
    "vulnerabilityscanfrequency": ("vulnerabilityScanFrequency", False),
    "criticalvulnerabilitycount": ("criticalVulnerabilityCount", None),
    "knownexploitedvulncount": ("knownExploitedVulnCount", None),
    "knownexploitedhighvulncount": ("knownExploitedHighVulnCount", None),
    "epsshighriskcriticalvulncount": ("epssHighRiskCriticalVulnCount", None),
    "epsshighriskhighvulncount": ("epssHighRiskHighVulnCount", None),
}


def value(name, payload):
    key = KEYS[name][0]
    return load(name).transform(payload)["transformedResponse"][key]


class FailClosed(unittest.TestCase):
    def test_every_key_fails_closed_on_no_evidence(self):
        for name, (key, fail) in KEYS.items():
            for body in FAILED_SCANS:
                with self.subTest(key=key, body=str(body)[:60]):
                    self.assertEqual(value(name, body), fail)


class Measured(unittest.TestCase):
    def test_asm_enabled(self):
        self.assertIs(value("isasmenabled", scan()), True)

    def test_inventory_count(self):
        self.assertEqual(value("externalassetinventorycount", scan()), 3)
        self.assertEqual(value("externalassetinventorycount", scan(totalDiscovered="40", domainsCapped=True)), 40)

    def test_scan_frequency_fresh_and_stale(self):
        self.assertIs(value("vulnerabilityscanfrequency", scan()), True)
        old = (datetime.utcnow() - timedelta(days=9)).isoformat()
        self.assertIs(value("vulnerabilityscanfrequency", scan(timestamp=old)), False)
        self.assertIs(value("vulnerabilityscanfrequency", scan(timestamp="")), False)

    def test_critical_count_flips(self):
        self.assertEqual(value("criticalvulnerabilitycount", scan(totalDiscovered="2")), 0)
        self.assertEqual(value("criticalvulnerabilitycount", scan(findings=[CRIT_KEV, CRIT])), 2)

    def test_kev_count_flips(self):
        self.assertEqual(value("knownexploitedvulncount", scan(findings=[CRIT])), 0)
        self.assertEqual(value("knownexploitedvulncount", scan(findings=[CRIT_KEV, CRIT])), 1)

    def test_one_unresponsive_host_still_measures(self):
        for name, (key, fail) in KEYS.items():
            with self.subTest(key=key):
                self.assertNotEqual(value(name, scan(totalDiscovered="2", **ONE_UNRESPONSIVE)), fail)
        self.assertEqual(value("criticalvulnerabilitycount", scan(findings=[CRIT], **ONE_UNRESPONSIVE)), 1)

    def test_wrapped_input(self):
        self.assertEqual(value("criticalvulnerabilitycount", {"apiResponse": scan(findings=[CRIT])}), 1)


class CriticalCountCappedScan(unittest.TestCase):
    """criticalVulnerabilityCount on a partial (capped) scan, 2 Oct 2026: the same guard noCriticalFindings got
    in TX #786/#788. Shapes follow the recorded inputSummary of the live Carlex and See to Solve scans."""

    def full(self, payload):
        return load("criticalvulnerabilitycount").transform(payload)

    def test_capped_clean_scan_is_unevaluated(self):
        # Carlex 2 Oct 01:04 ET: 25 of 45 discovered hosts scanned, 0 findings. Read 0 (a pass) before this fix.
        out = self.full(scan(primaryDomain="carlex.com", domainsScanned="25", totalDiscovered="45", domainsCapped="True",
                             templatesScanned="1675", domainResults=[]))
        tr, info = out["transformedResponse"], out["additionalInfo"]
        self.assertIsNone(tr["criticalVulnerabilityCount"])
        self.assertEqual(info["dataCollection"]["status"], "error")
        self.assertIn("Only 25 of 45 discovered host(s) of carlex.com were scanned", info["dataCollection"]["errors"][0])
        self.assertIn("not a clean estate", info["dataCollection"]["errors"][0])

    def test_numeric_short_without_flag_is_unevaluated(self):
        out = self.full(scan(domainsScanned="25", totalDiscovered="70", domainResults=[]))
        self.assertIsNone(out["transformedResponse"]["criticalVulnerabilityCount"])
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "error")

    def test_flag_alone_is_unevaluated(self):
        self.assertIsNone(value("criticalvulnerabilitycount", scan(totalDiscovered="2", domainsCapped=True)))

    def test_full_clean_scan_still_measures_zero(self):
        # See to Solve 2 Oct 01:04 ET: 20 of 20 hosts, 0 findings: a real zero.
        out = self.full(scan(primaryDomain="seetosolve.com", domainsScanned="20", totalDiscovered="20",
                             domainsCapped="False", domainResults=[]))
        self.assertEqual(out["transformedResponse"]["criticalVulnerabilityCount"], 0)
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")

    def test_critical_finding_on_a_capped_scan_is_a_lower_bound(self):
        out = self.full(scan(domainsScanned="25", totalDiscovered="45", domainsCapped="True", domainResults=[],
                             findings=[CRIT]))
        tr, info = out["transformedResponse"], out["additionalInfo"]
        self.assertEqual(tr["criticalVulnerabilityCount"], 1)
        self.assertEqual(info["dataCollection"]["status"], "success")
        self.assertTrue(any("Only 25 of 45" in r and "lower bound" in r for r in info["evaluation"]["failReasons"]))

    def test_empty_and_error_inputs_are_unevaluated_with_a_reason(self):
        for body in [{}, [], None, "", "{}", {"value": []}, {"data": []},
                     {"status": "error", "message": "Lambda HTTP 429: Rate Exceeded"},
                     {"error": "Unauthorized", "statusCode": 401}]:
            with self.subTest(body=str(body)[:60]):
                out = self.full(body)
                self.assertIsNone(out["transformedResponse"]["criticalVulnerabilityCount"])
                self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "error")
                self.assertTrue(out["additionalInfo"]["dataCollection"]["errors"])


if __name__ == "__main__":
    unittest.main()

# review-job smoke test (2 Oct); this PR is closed without merging.
