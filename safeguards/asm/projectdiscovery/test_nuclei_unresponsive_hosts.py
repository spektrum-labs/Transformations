"""noCriticalFindings / noHighFindings (asm/projectdiscovery/nuclei_transform.py): a host whose scans time out on
two consecutive runs (timing out on the latest) is excluded from the surface the keys are evaluated on.

Before 29 Oct 2026 any scan with fewer hosts scanned than discovered was a partial, and a clean partial was
Not evaluated. On an estate with one host that times out on every scan (Beacon, apis.*) the critical check
could never be evaluated. The Integration Service names such hosts in ``unresponsiveHosts`` with a reason
and their consecutive failures. Only two consecutive ``scan_timed_out`` failures exclude a host; IS's
``retried`` flag is a retry-budget marker (set on continuation errors, non-rediscovery and refusals too) and
is not read. SYNTHETIC bodies in IS's stored shape. Each case runs as plain Python and in the Token-Service
sandbox replica when it is installed.
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


def host(name, failures=1, reason="scan_timed_out", retried=False):
    h = {"domain": name, "status": "unresponsive", "reason": reason, "consecutiveTimeouts": failures, "findingsCount": 0}
    if retried:
        h["retried"] = True
    return h


def body(scanned=180, discovered=181, unresponsive=(), findings=(), capped=True, results=None, **extra):
    b = {
        "status": "success", "primaryDomain": "beacon.test", "domain": "beacon.test",
        "total": len(findings), "findings": list(findings),
        "domainResults": [{"domain": f"h{i}.beacon.test", "status": "success", "findingsCount": 0} for i in range(scanned)]
        if results is None else results,
        "domainsScanned": scanned, "totalDiscovered": discovered, "domainsCapped": capped,
        "unresponsiveHosts": list(unresponsive), "errors": [],
    }
    b.update(extra)
    return b


def keys(out):
    r = out["transformedResponse"]
    return r.get("noCriticalFindings"), r.get("noHighFindings")


def reasons(out):
    ev = out["additionalInfo"]["evaluation"]
    return ev["passReasons"], ev["failReasons"], out["additionalInfo"]["dataCollection"]["errors"]


def test_two_consecutive_timeouts_exclude_the_host_and_the_rest_is_evaluated():
    out = run(body(unresponsive=[host("apis.beacon.test", failures=2)]))
    assert keys(out) == (True, True)
    passes, fails, errors = reasons(out)
    assert errors == [] and fails == []
    note = [p for p in passes if "excluded from the surface evaluated" in p]
    assert len(note) == 1 and "scans of 1 of 181" in note[0] and "failed on two consecutive runs, timing out on the latest" in note[0]
    assert "apis.beacon.test" in note[0] and "did not answer" not in note[0]
    assert out["transformedResponse"]["unresponsiveHosts"] == ["apis.beacon.test"]
    assert out["transformedResponse"]["domainsScanned"] == 180 and out["transformedResponse"]["totalDiscovered"] == 181
    summary = out["additionalInfo"]["transformation"]["inputSummary"]
    assert summary["unresponsiveHosts"] == ["apis.beacon.test"] and summary["totalDiscovered"] == 181


def test_a_first_failure_keeps_the_partial_rule_and_names_the_host_as_to_be_retried():
    out = run(body(unresponsive=[host("apis.beacon.test", failures=1)]))
    assert keys(out) == (None, None)
    _passes, fails, errors = reasons(out)
    assert errors and "Only 180 of 181" in errors[0] and "not proof" in errors[0]
    assert "will be retried: apis.beacon.test" in errors[0]
    assert out["additionalInfo"]["transformation"]["inputSummary"]["unresponsiveHostsPending"] == ["apis.beacon.test"]


def test_retried_is_not_evidence_a_refused_continuation_at_count_one_stays_grey():
    """IS sets ``retried`` when the continuation failed on the host, but also when it ran out without reaching
    it or was refused over the ceiling (a systemic failure): a count-1 host stays pending whatever the flag."""
    assert keys(run(body(unresponsive=[host("apis.beacon.test", failures=1, retried=True)]))) == (None, None)


def test_a_scanner_error_never_excludes_a_host_whatever_the_count():
    out = run(body(unresponsive=[host("apis.beacon.test", failures=3, reason="scan_error")]))
    assert keys(out) == (None, None)
    assert "will be retried: apis.beacon.test" in reasons(out)[2][0]


def test_a_mix_of_excluded_and_pending_hosts_still_waits_for_the_retry():
    out = run(body(scanned=179, unresponsive=[host("a.beacon.test", 2), host("b.beacon.test", 1)]))
    assert keys(out) == (None, None)
    assert "will be retried: b.beacon.test" in reasons(out)[2][0]


def test_a_host_capped_scan_without_unresponsive_hosts_is_still_a_partial():
    out = run(body(scanned=25, discovered=181, unresponsive=[]))
    assert keys(out) == (None, None)
    assert "Only 25 of 181" in reasons(out)[2][0]


def test_the_arithmetic_must_be_exact():
    # 178 scanned + 1 excluded = 179 < 181: two hosts are simply unscanned.
    assert keys(run(body(scanned=178, unresponsive=[host("apis.beacon.test", 2)]))) == (None, None)
    # 180 scanned + 2 excluded = 182 > 181: the list claims more than the gap.
    assert keys(run(body(scanned=180, unresponsive=[host("a.beacon.test", 2), host("b.beacon.test", 2)]))) == (None, None)
    # domainsScanned says 180 but domainResults holds 179 rows: the counts do not agree.
    rows = [{"domain": f"h{i}.beacon.test", "status": "success"} for i in range(179)]
    assert keys(run(body(scanned=180, unresponsive=[host("apis.beacon.test", 2)], results=rows))) == (None, None)


def test_a_duplicated_host_counts_once():
    out = run(body(unresponsive=[host("apis.beacon.test", 2), host("apis.beacon.test", 2)]))
    assert keys(out) == (True, True)
    assert out["transformedResponse"]["unresponsiveHosts"] == ["apis.beacon.test"]
    # ...and two listings of one host do not explain a two-host gap.
    assert keys(run(body(scanned=179, unresponsive=[host("apis.beacon.test", 2), host("apis.beacon.test", 2)]))) == (None, None)


def test_a_missing_or_malformed_domain_results_keeps_the_partial_rule():
    """Without the per-host list the overlap and arithmetic checks cannot be made (IS's
    _honest_unresponsive_partial refuses a non-list too): 3 of 4 scanned with one host at count 2 stays grey."""
    b = body(scanned=3, discovered=4, unresponsive=[host("a.beacon.test", 2)])
    del b["domainResults"]
    assert keys(run(b)) == (None, None)
    b = body(scanned=3, discovered=4, unresponsive=[host("a.beacon.test", 2)])
    b["domainResults"] = "3 hosts"
    assert keys(run(b)) == (None, None)
    b = body(scanned=3, discovered=4, unresponsive=[host("a.beacon.test", 2)])
    b["domainResults"] = None
    assert keys(run(b)) == (None, None)
    # ...and the same body with the list present evaluates.
    assert keys(run(body(scanned=3, discovered=4, unresponsive=[host("a.beacon.test", 2)]))) == (True, True)


def test_a_host_that_is_also_in_domain_results_explains_nothing():
    assert keys(run(body(unresponsive=[host("h0.beacon.test", 2)]))) == (None, None)


def test_an_entry_without_a_host_name_or_a_malformed_list_explains_nothing():
    assert keys(run(body(unresponsive=[{"status": "unresponsive", "consecutiveTimeouts": 2}]))) == (None, None)
    assert keys(run(body(unresponsive=[host("", 2)]))) == (None, None)
    assert keys(run(body(unresponsive=[host("apis.beacon.test", 2), "not-a-dict"]))) == (None, None)
    assert keys(run(body(unresponsive="apis.beacon.test"))) == (None, None)


def test_a_time_limited_scan_is_never_evaluated_on_exclusions():
    assert keys(run(body(unresponsive=[host("apis.beacon.test", 2)], scanTimeLimited=True))) == (None, None)


def test_a_finding_on_a_scanned_host_still_fails_with_the_excluded_host_named():
    finding = {"info": {"severity": "high", "name": "Exposed panel"}, "host": "h1.beacon.test"}
    out = run(body(unresponsive=[host("apis.beacon.test", 2)], findings=[finding]))
    assert keys(out) == (True, False)
    passes, fails, _errors = reasons(out)
    assert any("1 high severity finding" in f for f in fails)
    assert any("excluded from the surface evaluated" in p for p in passes)


def test_more_than_ten_hosts_are_counted_not_listed_and_names_are_bounded():
    hosts = [host(f"u{i}.beacon.test", 2) for i in range(12)]
    out = run(body(scanned=108, discovered=120, unresponsive=hosts))   # 12 of 120: at the 10% ceiling
    assert keys(out) == (True, True)
    note = [p for p in reasons(out)[0] if "excluded from the surface evaluated" in p][0]
    assert "scans of 12 of 120" in note and "and 2 more" in note and "u11.beacon.test" not in note
    long_name = "x" * 400 + ".beacon.test"
    out = run(body(unresponsive=[host(long_name, 2)]))
    assert keys(out) == (True, True)
    assert len(out["transformedResponse"]["unresponsiveHosts"][0]) == 253


def test_the_excluded_share_is_bounded_like_the_integration_services_ceiling():
    """One scanned host and 180 chronic timeouts is not a clean 181-host estate: past 10% of the discovered
    hosts (one always allowed) the gap is the scanner's, the network's or a blackhole, and the partial rule
    stands, saying so."""
    many = [host(f"u{i}.beacon.test", 2) for i in range(180)]
    out = run(body(scanned=1, discovered=181, unresponsive=many))
    assert keys(out) == (None, None)
    assert "180 host(s) have failed on repeated scans, more than the 18 this estate may exclude" in reasons(out)[2][0]
    # 19 of 181 is over the ceiling (18); 18 is at it.
    assert keys(run(body(scanned=162, discovered=181, unresponsive=[host(f"u{i}.beacon.test", 2) for i in range(19)]))) == (None, None)
    assert keys(run(body(scanned=163, discovered=181, unresponsive=[host(f"u{i}.beacon.test", 2) for i in range(18)]))) == (True, True)
    # A small estate may still exclude one host.
    assert keys(run(body(scanned=4, discovered=5, unresponsive=[host("a.beacon.test", 2)]))) == (True, True)
    assert keys(run(body(scanned=3, discovered=5, unresponsive=[host("a.beacon.test", 2), host("b.beacon.test", 2)]))) == (None, None)


def test_an_unscanned_body_is_never_evaluated_on_excluded_hosts_alone():
    out = run(body(scanned=0, discovered=2, unresponsive=[host("a.beacon.test", 2), host("b.beacon.test", 2)]))
    assert keys(out) == (None, None)
