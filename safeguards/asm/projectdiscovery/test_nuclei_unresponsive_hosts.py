"""noCriticalFindings / noHighFindings (asm/projectdiscovery/nuclei_transform.py): a host that does not
answer the scanner is unresponsive surface, not unscanned surface.

Before 29 Oct 2026 any scan with fewer hosts scanned than discovered was a partial, and a clean partial was
Not evaluated. On an estate with one host that times out on every scan (Beacon, apis.*) the critical check
could never be evaluated. The Integration Service already names such hosts in ``unresponsiveHosts`` with
their consecutive failures and whether its continuation retried them. SYNTHETIC bodies in that shape. Each
case runs as plain Python and in the Token-Service sandbox replica when it is installed.
"""
import copy
import importlib.util
import pathlib

import pytest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]
TAG = "nucleiunresponsive"
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

SOURCE = (HERE / "nuclei_transform.py").read_text()


def run(body):
    return load_code(SOURCE, "nuclei_transform.py")["transform"](copy.deepcopy(body))


def host(name, failures=1, retried=False):
    h = {"domain": name, "status": "unresponsive", "reason": "scan_timed_out",
         "consecutiveTimeouts": failures, "findingsCount": 0}
    if retried:
        h["retried"] = True
    return h


def body(scanned=180, discovered=181, unresponsive=(), findings=(), capped=True):
    return {
        "status": "success", "primaryDomain": "beacon.test", "domain": "beacon.test",
        "total": len(findings), "findings": list(findings),
        "domainResults": [{"domain": f"h{i}.beacon.test", "status": "success", "findingsCount": 0} for i in range(scanned)],
        "domainsScanned": scanned, "totalDiscovered": discovered, "domainsCapped": capped,
        "unresponsiveHosts": list(unresponsive), "errors": [],
    }


def keys(out):
    r = out["transformedResponse"]
    return r.get("noCriticalFindings"), r.get("noHighFindings")


def reasons(out):
    ev = out["additionalInfo"]["evaluation"]
    return ev["passReasons"], ev["failReasons"], out["additionalInfo"]["dataCollection"]["errors"]


def test_a_host_that_failed_two_consecutive_scans_is_unresponsive_surface_and_the_rest_is_evaluated():
    out = run(body(unresponsive=[host("apis.beacon.test", failures=2)]))
    assert keys(out) == (True, True)
    passes, fails, errors = reasons(out)
    assert errors == [] and fails == []
    note = [p for p in passes if "unresponsive surface" in p]
    assert len(note) == 1 and "1 of 181" in note[0] and "apis.beacon.test" in note[0]
    assert out["transformedResponse"]["unresponsiveHosts"] == ["apis.beacon.test"]
    assert out["transformedResponse"]["domainsScanned"] == 180


def test_a_host_the_continuation_retried_and_lost_again_is_written_off_the_same_day():
    out = run(body(unresponsive=[host("apis.beacon.test", failures=1, retried=True)]))
    assert keys(out) == (True, True)


def test_a_first_failure_the_continuation_will_retry_keeps_the_partial_rule_and_names_the_host():
    out = run(body(unresponsive=[host("apis.beacon.test", failures=1)]))
    assert keys(out) == (None, None)
    _passes, fails, errors = reasons(out)
    assert errors and "Only 180 of 181" in errors[0] and "not proof" in errors[0]
    assert "will be retried: apis.beacon.test" in errors[0]
    assert out["additionalInfo"]["transformation"]["inputSummary"]["unresponsiveHostsPending"] == ["apis.beacon.test"]


def test_a_mix_of_written_off_and_pending_hosts_still_waits_for_the_retry():
    out = run(body(scanned=179, unresponsive=[host("a.beacon.test", 2), host("b.beacon.test", 1)]))
    assert keys(out) == (None, None)
    assert "b.beacon.test" in reasons(out)[2][0] and "a.beacon.test" not in reasons(out)[2][0].split("retried")[1]


def test_a_host_capped_scan_without_unresponsive_hosts_is_still_a_partial():
    out = run(body(scanned=25, discovered=181, unresponsive=[]))
    assert keys(out) == (None, None)
    assert "Only 25 of 181" in reasons(out)[2][0]


def test_unresponsive_hosts_do_not_explain_a_wider_gap():
    # 178 scanned + 1 written off = 179 < 181: two hosts are simply unscanned.
    out = run(body(scanned=178, unresponsive=[host("apis.beacon.test", 2)]))
    assert keys(out) == (None, None)


def test_a_finding_on_an_answering_host_still_fails_with_the_unresponsive_host_named():
    finding = {"info": {"severity": "high", "name": "Exposed panel"}, "host": "h1.beacon.test"}
    out = run(body(unresponsive=[host("apis.beacon.test", 2)], findings=[finding]))
    assert keys(out) == (True, False)
    passes, fails, _errors = reasons(out)
    assert any("1 high severity finding" in f for f in fails)
    assert any("unresponsive surface" in p for p in passes)


def test_more_than_ten_hosts_are_counted_not_listed():
    hosts = [host(f"u{i}.beacon.test", 2) for i in range(12)]
    out = run(body(scanned=169, unresponsive=hosts))
    assert keys(out) == (True, True)
    note = [p for p in reasons(out)[0] if "unresponsive surface" in p][0]
    assert "12 of 181" in note and "and 2 more" in note and "u11.beacon.test" not in note


def test_an_unscanned_body_is_never_evaluated_on_unresponsive_hosts_alone():
    out = run(body(scanned=0, discovered=2, unresponsive=[host("a.beacon.test", 2), host("b.beacon.test", 2)]))
    assert keys(out) == (None, None)
