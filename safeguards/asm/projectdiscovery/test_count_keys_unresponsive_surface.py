"""KEV, EPSS and criticalVulnerabilityCount read the unresponsive-surface rule the way noCriticalFindings does.

nuclei_transform.py (noCriticalFindings / noHighFindings) excludes a host that failed on two consecutive runs and
timed out on the latest from the surface it evaluates. The count keys read the same stored scan, but until now
they kept the plain partial rule, so on an estate with one such host noCriticalFindings passed while
knownExploitedVulnCount and epssHighRiskCriticalVulnCount on the very same scan were Not evaluated. These cases
pin the two readings together. SYNTHETIC bodies in the Integration Service's stored shape. Each case runs as
plain Python and in the Token-Service sandbox replica when it is installed.
"""
import copy
import importlib.util
import pathlib

import pytest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]
TAG = "countkeyssurface"
try:
    import RestrictedPython  # noqa: F401
    spec = importlib.util.spec_from_file_location("restricted_sandbox_" + TAG, ROOT / "tools" / "restricted_sandbox.py")
    sandbox = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sandbox)
    load_code = sandbox.load
except ImportError:
    def load_code(code, filename):
        ns = {"__name__": TAG + "_sandbox"}
        exec(compile(code, filename, "exec"), ns)
        return ns

KEYS = {
    "knownexploitedvulncount": "knownExploitedVulnCount",
    "knownexploitedhighvulncount": "knownExploitedHighVulnCount",
    "epsshighriskcriticalvulncount": "epssHighRiskCriticalVulnCount",
    "epsshighriskhighvulncount": "epssHighRiskHighVulnCount",
    "criticalvulnerabilitycount": "criticalVulnerabilityCount",
}
SOURCES = {name: (HERE / (name + ".py")).read_text() for name in KEYS}
NUCLEI = (HERE / "nuclei_transform.py").read_text()


def run(name, body):
    return load_code(SOURCES[name], name + ".py")["transform"](copy.deepcopy(body))


def value(name, out):
    return out["transformedResponse"][KEYS[name]]


def host(name, failures=1, reason="scan_timed_out"):
    return {"domain": name, "status": "unresponsive", "reason": reason, "consecutiveTimeouts": failures, "findingsCount": 0}


def body(scanned=181, discovered=182, unresponsive=(), findings=(), capped=True, results=None, **extra):
    b = {
        "status": "success", "primaryDomain": "example.test", "domain": "example.test",
        "total": len(findings), "findings": list(findings), "templatesScanned": 1866,
        "domainResults": [{"domain": "h" + str(i) + ".example.test", "status": "success", "findingsCount": 0}
                          for i in range(scanned)] if results is None else results,
        "domainsScanned": scanned, "domainsResponsive": scanned, "totalDiscovered": discovered,
        "domainsCapped": capped, "unresponsiveHosts": list(unresponsive), "errors": [],
    }
    b.update(extra)
    return b


ALL = sorted(KEYS)


@pytest.mark.parametrize("name", ALL)
def test_one_host_timed_out_twice_is_excluded_and_zero_is_a_measured_answer(name):
    out = run(name, body(unresponsive=[host("apis.example.test", failures=2)]))
    assert value(name, out) == 0
    info = out["additionalInfo"]
    assert info["dataCollection"]["status"] != "error"
    note = [p for p in info["evaluation"]["passReasons"] if "excluded from the surface evaluated" in p]
    assert len(note) == 1 and "scans of 1 of 182" in note[0] and "apis.example.test" in note[0]
    assert info["transformation"]["inputSummary"]["unresponsiveHostsExcluded"] == ["apis.example.test"]


@pytest.mark.parametrize("name", ALL)
def test_the_count_key_and_no_critical_findings_agree_on_one_scan(name):
    b = body(unresponsive=[host("apis.example.test", failures=2)])
    nuclei = load_code(NUCLEI, "nuclei_transform.py")["transform"](copy.deepcopy(b))
    assert nuclei["transformedResponse"]["noCriticalFindings"] is True
    assert value(name, run(name, b)) == 0


@pytest.mark.parametrize("name", ALL)
def test_a_first_failure_keeps_the_partial_rule_and_names_the_host(name):
    out = run(name, body(unresponsive=[host("apis.example.test", failures=1)]))
    assert value(name, out) is None
    errors = out["additionalInfo"]["dataCollection"]["errors"]
    assert errors and "Only 181 of 182" in errors[0] and "not proof" in errors[0]
    assert "will be retried: apis.example.test" in errors[0]
    assert out["additionalInfo"]["transformation"]["inputSummary"]["unresponsiveHostsPending"] == ["apis.example.test"]


@pytest.mark.parametrize("name", ALL)
def test_a_scanner_error_never_excludes_a_host(name):
    out = run(name, body(unresponsive=[host("_dmarc.example.test", failures=3, reason="scan_error")]))
    assert value(name, out) is None


@pytest.mark.parametrize("name", ALL)
def test_a_host_capped_scan_is_still_a_partial(name):
    assert value(name, run(name, body(scanned=25, discovered=182))) is None


@pytest.mark.parametrize("name", ALL)
def test_the_arithmetic_must_be_exact(name):
    # 180 scanned + 1 excluded = 181 < 182: a host is simply unscanned.
    assert value(name, run(name, body(scanned=180, unresponsive=[host("apis.example.test", 2)]))) is None
    # too many excluded for the estate (10%, at least one): 2 of 4.
    two = body(scanned=2, discovered=4, unresponsive=[host("a.example.test", 2), host("b.example.test", 2)])
    assert value(name, run(name, two)) is None


@pytest.mark.parametrize("name", ALL)
def test_a_time_limited_scan_is_never_complete(name):
    out = run(name, body(unresponsive=[host("apis.example.test", 2)], scanTimeLimited=True))
    assert value(name, out) is None


@pytest.mark.parametrize("name", ALL)
def test_a_scan_with_nothing_missing_is_unchanged(name):
    out = run(name, body(scanned=182, discovered=182, capped=False))
    assert value(name, out) == 0
    assert not any("excluded" in p for p in out["additionalInfo"]["evaluation"]["passReasons"])


def kev_critical(host_name):
    """A synthetic live critical KEV finding with a high EPSS percentile: it counts for every critical key."""
    return {
        "template-id": "CVE-2021-44228", "host": host_name, "matched-at": "https://" + host_name + "/",
        "matcher-status": True, "type": "http",
        "info": {"name": "Synthetic KEV", "severity": "critical", "tags": ["cve", "kev"],
                 "classification": {"cve-id": ["cve-2021-44228"], "epss-score": 0.9, "epss-percentile": 0.99}},
    }


@pytest.mark.parametrize("name", ["knownexploitedvulncount", "epsshighriskcriticalvulncount", "criticalvulnerabilitycount"])
def test_a_finding_on_a_covered_surface_is_counted_and_the_exclusion_is_named(name):
    out = run(name, body(unresponsive=[host("apis.example.test", failures=2)], findings=[kev_critical("h1.example.test")]))
    assert value(name, out) == 1
    ev = out["additionalInfo"]["evaluation"]
    assert not any(p.startswith("Only ") for p in ev["failReasons"])
    assert any("excluded from the surface evaluated" in p for p in ev["passReasons"])
