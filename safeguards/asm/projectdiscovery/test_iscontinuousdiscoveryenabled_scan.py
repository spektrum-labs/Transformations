"""isContinuousDiscoveryEnabled (scan-backed) for ProjectDiscovery OS.

Fixtures are the real-shaped runParallelASMScan bodies already used by test_exploitable_keys.py and
test_asm_keys.py (IS src/models/integrations/asm/nuclei.py). The seed domain is always the first domainResults
entry; subfinder output follows it, and a subfinder failure leaves only the seed.
"""
import copy
import importlib.util
import json
import unittest
from datetime import datetime, timedelta
from pathlib import Path

HERE = Path(__file__).parent
KEY = "isContinuousDiscoveryEnabled"


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MOD = load("iscontinuousdiscoveryenabled_scan")
EXPLOITABLE = load("test_exploitable_keys")
ASM = load("test_asm_keys")
scan = EXPLOITABLE.scan


def run(payload):
    return MOD.transform(payload)


def value(payload):
    return run(payload)["transformedResponse"][KEY]


def seed_only(**overrides):
    # What IS emits when subfinder errors, times out or finds nothing: only the seed is scanned.
    body = scan(domainsScanned=1, totalDiscovered=1,
                domainResults=[{"domain": "example.com", "findingsCount": 0, "status": "success"}])
    body.update(overrides)
    return body


def capped_scan():
    hosts = ["example.com"] + ["h" + str(i) + ".example.com" for i in range(24)]
    return scan(domainsScanned=25, totalDiscovered=80, domainsCapped=True,
                domainResults=[{"domain": h, "findingsCount": 0, "status": "success"} for h in hosts])


class FailClosed(unittest.TestCase):
    BODIES = {
        "none": None,
        "empty dict": {},
        "empty string": "",
        "not json": "not json",
        "empty scan": EXPLOITABLE.EMPTY_SCAN,
        "rate limited 429": EXPLOITABLE.ERROR_ENVELOPE,
        "lambda timeout": {"status": "error", "message": "Lambda invocation timed out", "domain": "example.com"},
        "scan not executed": {"status": "error", "message": "ASM scan not executed"},
        "template-list fallback (single domain, no discovery)":
            {"status": "success", "domain": "example.com", "findings": [], "total": 0},
        "zero hosts scanned": scan(domainsScanned=0, totalDiscovered=0, domainResults=[]),
        "zero templates": scan(templatesScanned=0),
        "host errored": scan(errors=[{"domain": "www.example.com", "error": "Lambda invocation timed out"}]),
        "host status error": scan(domainResults=[
            {"domain": "example.com", "findingsCount": 0, "status": "success"},
            {"domain": "www.example.com", "findingsCount": 0, "status": "error"},
            {"domain": "app.example.com", "findingsCount": 0, "status": "success"}]),
        "findings list truncated": scan([EXPLOITABLE.LOG4J], total=5),
        "no findings list": dict(scan(), findings=None),
        "domainResults truncated": scan(domainResults=[
            {"domain": "example.com", "findingsCount": 0, "status": "success"}]),
        "domainResults missing": dict(scan(), domainResults=None),
        "totalDiscovered missing": dict(scan(), totalDiscovered=None),
        "discovered below scanned": scan(totalDiscovered=2),
        "capped flag without extra hosts": scan(domainsCapped=True),
        "no primaryDomain": dict(scan(), primaryDomain=None),
        "subfinder found nothing (seed only)": seed_only(),
        "seed listed twice": scan(domainsScanned=2, totalDiscovered=2, domainResults=[
            {"domain": "example.com", "findingsCount": 0, "status": "success"},
            {"domain": "EXAMPLE.com.", "findingsCount": 0, "status": "success"}]),
        "stale scan": scan(timestamp=(datetime.utcnow() - timedelta(days=3)).isoformat()),
        "no timestamp": scan(timestamp=""),
        "garbage timestamp": scan(timestamp="yesterday"),
        "future timestamp": scan(timestamp=(datetime.utcnow() + timedelta(days=2)).isoformat()),
        "validation failed": {"data": scan(), "validation": {"status": "failed", "errors": ["x"], "warnings": []}},
    }

    def test_no_evidence_is_false_with_error(self):
        for label, body in self.BODIES.items():
            with self.subTest(body=label):
                out = run(copy.deepcopy(body))
                self.assertIs(out["transformedResponse"][KEY], False)
                self.assertEqual(out["transformedResponse"], {KEY: False})
                self.assertEqual(out["additionalInfo"]["transformation"]["status"], "error")
                self.assertTrue(out["additionalInfo"]["evaluation"]["failReasons"])
                self.assertEqual(out["additionalInfo"]["evaluation"]["passReasons"], [])

    def test_sibling_failed_scan_battery(self):
        for body in ASM.FAILED_SCANS:
            with self.subTest(body=str(body)[:60]):
                self.assertIs(value(copy.deepcopy(body)), False)

    def test_seed_only_names_the_discovery_failure(self):
        errors = run(seed_only())["additionalInfo"]["dataCollection"]["errors"]
        self.assertTrue(any("no host beyond the seed" in e for e in errors))


class Discovered(unittest.TestCase):
    def test_completed_scan_with_hosts_is_true(self):
        out = run(scan())
        self.assertIs(out["transformedResponse"][KEY], True)
        self.assertEqual(out["transformedResponse"]["hostsDiscovered"], 3)
        self.assertEqual(out["transformedResponse"]["subdomainsDiscovered"], 2)
        self.assertIs(out["transformedResponse"]["discoveryCapped"], False)
        self.assertTrue(out["additionalInfo"]["evaluation"]["passReasons"])
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")

    def test_findings_do_not_change_the_answer(self):
        self.assertIs(value(scan([EXPLOITABLE.LOG4J, EXPLOITABLE.LOW_EPSS])), True)

    def test_capped_discovery_still_counts(self):
        out = run(capped_scan())
        self.assertIs(out["transformedResponse"][KEY], True)
        self.assertEqual(out["transformedResponse"]["hostsDiscovered"], 80)
        self.assertIs(out["transformedResponse"]["discoveryCapped"], True)
        self.assertTrue(out["additionalInfo"]["evaluation"]["additionalFindings"])

    def test_string_counts_wrapped_and_json_input(self):
        body = scan(domainsScanned="3", totalDiscovered="3", total="0", templatesScanned="1853")
        self.assertIs(value(body), True)
        self.assertIs(value({"apiResponse": {"response": body}}), True)
        self.assertIs(value(json.dumps(scan())), True)
        self.assertIs(value(scan(timestamp=datetime.utcnow().isoformat() + "Z")), True)
        self.assertIs(value(scan(timestamp=datetime.utcnow().isoformat() + "+00:00")), True)

    def test_flips_on_the_same_shape(self):
        self.assertIs(value(scan()), True)
        self.assertIs(value(seed_only()), False)

    def test_schema_version_and_sections(self):
        out = run(scan())
        self.assertEqual(set(out["additionalInfo"]),
                         {"dataCollection", "validation", "transformation", "evaluation", "metadata"})
        self.assertEqual(out["additionalInfo"]["metadata"]["schemaVersion"], "2.0")
        self.assertEqual(out["additionalInfo"]["metadata"]["transformationId"], KEY)


if __name__ == "__main__":
    unittest.main()
