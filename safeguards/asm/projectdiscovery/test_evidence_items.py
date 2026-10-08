"""evidenceItems for gap disputes on the ProjectDiscovery (nuclei ASM) transformations.

Every host below is an example domain. The transformations are loaded through tools/restricted_sandbox.py,
the mirror of the production sandbox (which allows no hashlib), and their pure-Python SHA-256 is compared with
hashlib's.
"""
import copy
import hashlib
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE.parents[2] / "tools"))

import restricted_sandbox  # noqa: E402

FILES = {
    "nuclei_transform": ["noCriticalFindings", "noHighFindings"],
    "criticalvulnerabilitycount": ["criticalVulnerabilityCount"],
    "knownexploitedvulncount": ["knownExploitedVulnCount"],
    "knownexploitedhighvulncount": ["knownExploitedHighVulnCount"],
    "epsshighriskcriticalvulncount": ["epssHighRiskCriticalVulnCount"],
    "epsshighriskhighvulncount": ["epssHighRiskHighVulnCount"],
}
MODULES = {n: restricted_sandbox.load((HERE / (n + ".py")).read_text(), n + ".py") for n in FILES}


def finding(template_id, severity, matched_at, tags=("exposure",), **extra):
    event = {"template-id": template_id, "matched-at": matched_at, "host": "ignored.example.test",
             "info": {"name": template_id, "severity": severity, "tags": list(tags),
                      "classification": {"cve-id": ["cve-2021-0001"], "epss-percentile": 0.99, "epss-score": 0.9}}}
    event.update(extra)
    return event


def scan(findings, **overrides):
    body = {"status": "success", "primaryDomain": "example.com", "findings": copy.deepcopy(findings),
            "total": len(findings), "domainsScanned": 2, "totalDiscovered": 2, "domainsCapped": False,
            "domainResults": [{"domain": "example.com", "findingsCount": 0, "status": "success"},
                              {"domain": "autoconfig.example.com", "findingsCount": 0, "status": "success"}],
            "templatesScanned": 100, "errors": [], "timestamp": "2026-01-01T00:00:00"}
    body.update(overrides)
    return body


CREDS = finding("dot-credentials", "high", "https://autoconfig.example.com/.credentials?x=1#top")
KEV = finding("kev-template", "critical", "https://app.example.com/login", tags=("cve", "kev"))
CRIT = finding("crit-template", "critical", "https://app.example.com/admin/")
OFFENDING = {  # the finding that makes each file fail, and the scan it needs
    "nuclei_transform": [CREDS, CRIT],
    "criticalvulnerabilitycount": [CRIT],
    "knownexploitedvulncount": [KEV],
    "knownexploitedhighvulncount": [KEV],
    "epsshighriskcriticalvulncount": [KEV],
    "epsshighriskhighvulncount": [KEV],
}


def result(name, body):
    return MODULES[name]["transform"](body)["transformedResponse"]


class Fingerprint(unittest.TestCase):
    def test_sha256_matches_hashlib_in_every_file(self):
        samples = ["", "abc", "x" * 55, "x" * 56, "x" * 63, "x" * 64, "x" * 65, "t|https://a.example.com/p" * 40,
                   "teméplate|https://h.example.test/ü"]
        for name, ns in MODULES.items():
            for text in samples:
                self.assertEqual(ns["sha256_hex"](text), hashlib.sha256(text.encode("utf-8")).hexdigest(), name)

    def test_helper_block_is_identical_in_every_file(self):
        blocks = set()
        for name in MODULES:
            text = (HERE / (name + ".py")).read_text()
            blocks.add(text[text.index("# --- evidenceItems"):text.index("# --- end evidenceItems")])
        self.assertEqual(len(blocks), 1)

    def test_normalisation(self):
        norm = MODULES["criticalvulnerabilitycount"]["normalise_location"]
        same = ["https://Host.Example.com:443/a/b/?q=1#f", "HTTPS://host.example.com/a/b", "https://host.example.com./a/b//",
                "https://user:pw@host.example.com/a/b"]
        for value in same:
            self.assertEqual(norm(value), ("https", "host.example.com", "/a/b"), value)
        self.assertEqual(norm("https://h.example.com/"), norm("https://h.example.com"))
        self.assertEqual(norm("http://h.example.com:80/x"), ("http", "h.example.com", "/x"))
        self.assertEqual(norm("http://h.example.com:8080/x"), ("http", "h.example.com:8080", "/x"))
        self.assertEqual(norm("https://h.example.com:80/x")[1], "h.example.com:80")
        self.assertEqual(norm("h.example.com:22"), ("unknown", "h.example.com:22", ""))
        self.assertEqual(norm("https://[2001:db8::1]:443/p"), ("https", "[2001:db8::1]", "/p"))
        self.assertEqual(norm("https://h.example.com/Case"), ("https", "h.example.com", "/Case"))
        self.assertNotEqual(norm("https://h.example.com/Case"), norm("https://h.example.com/case"))
        self.assertEqual(norm(None), ("unknown", "unknown", ""))

    def test_credentials_finding_on_example_autoconfig_host(self):
        item = MODULES["criticalvulnerabilitycount"]["evidence_item"](CREDS)
        want = hashlib.sha256(b"dot-credentials|https://autoconfig.example.com/.credentials").hexdigest()
        self.assertEqual(item, {"fingerprint": want, "kind": "asm_finding",
                                "label": "dot-credentials at autoconfig.example.com/.credentials",
                                "severity": "high"})


class Items(unittest.TestCase):
    def test_every_file_emits_items_for_offending_findings_only(self):
        for name in FILES:
            noise = [finding("info-template", "info", "https://x.example.com/"),
                     finding("low-template", "low", "https://y.example.com/")]
            out = result(name, scan(OFFENDING[name] + noise))
            items = out["evidenceItems"]
            self.assertEqual(len(items), len(OFFENDING[name]), name)
            self.assertEqual([i["fingerprint"] for i in items], sorted(i["fingerprint"] for i in items), name)
            for item in items:
                self.assertEqual(set(item), {"fingerprint", "kind", "label", "severity"})
                self.assertEqual(item["kind"], "asm_finding")
                self.assertEqual(len(item["fingerprint"]), 64)
                self.assertIn(item["severity"], ("critical", "high"))

    def test_rescan_with_changed_counts_keeps_fingerprints_and_new_item_is_new(self):
        for name in FILES:
            first = scan(OFFENDING[name], timestamp="2026-01-01T00:00:00")
            again = scan(list(reversed(OFFENDING[name])) + [finding("low-template", "low", "https://z.example.com/")],
                         timestamp="2026-02-02T00:00:00", templatesScanned=999, domainsScanned=3,
                         totalDiscovered=3, domainResults=scan([])["domainResults"] * 2)
            before = {i["fingerprint"] for i in result(name, first)["evidenceItems"]}
            after = {i["fingerprint"] for i in result(name, again)["evidenceItems"]}
            self.assertEqual(before, after, name)
            new = finding("new-template", "critical", "https://new.example.com/", tags=("cve", "kev"))
            grown = {i["fingerprint"] for i in result(name, scan(OFFENDING[name] + [new]))["evidenceItems"]}
            self.assertTrue(before < grown and len(grown - before) == 1, name)

    def test_duplicate_hits_on_one_url_collapse_and_query_is_ignored(self):
        a = finding("kev-template", "critical", "https://app.example.com/login?a=1", tags=("kev",))
        b = finding("kev-template", "critical", "https://APP.example.com:443/login/", tags=("kev",))
        self.assertEqual(len(result("knownexploitedvulncount", scan([a, b]))["evidenceItems"]), 1)

    def test_no_items_and_unchanged_result_when_nothing_offends(self):
        for name, keys in FILES.items():
            out = result(name, scan([finding("info-template", "info", "https://x.example.com/")]))
            self.assertNotIn("evidenceItems", out, name)

    def test_verdict_output_is_otherwise_unchanged(self):
        for name, keys in FILES.items():
            out = MODULES[name]["transform"](scan(OFFENDING[name]))
            stripped = {k: v for k, v in out["transformedResponse"].items() if k != "evidenceItems"}
            self.assertIn(keys[0], stripped)
            self.assertNotIn("evidenceItems", stripped)
            if name == "nuclei_transform":
                self.assertEqual(stripped["noCriticalFindings"], False)
                self.assertEqual(stripped["noHighFindings"], False)
            else:
                self.assertEqual(stripped[keys[0]], len(OFFENDING[name]))

    def test_unevaluated_results_carry_no_items(self):
        out = result("criticalvulnerabilitycount", scan([CRIT], status="error"))
        self.assertNotIn("evidenceItems", out)


if __name__ == "__main__":
    unittest.main()
