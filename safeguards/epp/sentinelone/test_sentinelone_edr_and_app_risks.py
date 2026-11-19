"""SentinelOne (2bc425fa): isEDRDeployed from getEndpoints and the three vulnerability counts from the
getApplicationRiskCounts workflow (five GET /web/api/v2.1/application-management/risks?countOnly=true steps).
SYNTHETIC fixtures only.

Shapes: the IS response for GET /agents ({"data": [...], "pagination": {"totalItems", "nextCursor"}}) and the
workflow's keyed count blocks, bare and inside the Token-Service envelope. Each case runs as plain
Python and in the Token-Service sandbox replica.
"""
import copy
import json
import importlib.util
import pathlib
from datetime import datetime, timedelta

import pytest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]

TAG = "s1edr"
try:
    import RestrictedPython  # noqa: F401
    spec = importlib.util.spec_from_file_location("restricted_sandbox_" + TAG, ROOT / "tools" / "restricted_sandbox.py")
    sandbox = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sandbox)
    load_code = sandbox.load
except ImportError:
    # without RestrictedPython the "sandbox" leg runs as plain exec (CI installs requirements-test.txt,
    # which carries RestrictedPython, so CI runs the real sandbox)
    def load_code(code, filename):
        ns = {"__name__": TAG + "_sandbox"}
        exec(compile(code, filename, "exec"), ns)
        return ns

MODES = ["python", "sandbox"]


def load(name, mode):
    path = HERE / (name + ".py")
    if mode == "sandbox":
        return load_code(path.read_text(), "<transformation>")["transform"]
    spec = importlib.util.spec_from_file_location(TAG + "_" + name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.transform


def run(name, key, body, mode):
    out = load(name, mode)(copy.deepcopy(body))
    return out["transformedResponse"].get(key), out["additionalInfo"]["dataCollection"]["status"], out


def ts(body):
    return {"data": body, "validation": {"status": "skipped", "errors": [], "warnings": []}}


def iso(days_ago):
    return (datetime.utcnow() - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%S.000000Z")


NO_EVIDENCE = [None, {}, [], "", {"error": True, "statusCode": 403, "message": "Forbidden"},
               {"errors": [{"code": 4030010, "title": "Insufficient permissions"}]},
               {"error": True, "statusCode": 412, "message": "Required integration credentials are not connected"}]
VULN = ["openCriticalVulnerabilitiesCount", "openHighSeverityVulnerabilitiesCount", "overdueCriticalHighVulnerabilitiesCount"]


def agent(i, edr=True, days=0, uninstalled=False):
    return {"id": str(i), "uuid": "u" + str(i), "computerName": "host" + str(i), "isActive": True,
            "isUninstalled": uninstalled, "isDecommissioned": False, "mitigationMode": "protect",
            "activeProtection": ["edr"] if edr else [], "lastActiveDate": iso(days)}


def agents_body(agents, total=None, cursor=None, truncated=None):
    pag = {"totalItems": len(agents) if total is None else total, "nextCursor": cursor}
    if truncated is not None:
        pag["truncated"] = truncated
    return {"data": agents, "pagination": pag}


def count(total):
    """The IS block of one GET .../application-management/risks?countOnly=true step."""
    return {"data": [], "pagination": {"totalItems": total, "nextCursor": None}}


def counts(all_risks=500, critical=7, high=40, overdue_critical=2, overdue_high=11):
    return {"allRisks": count(all_risks), "critical": count(critical), "high": count(high),
            "overdueCritical": count(overdue_critical), "overdueHigh": count(overdue_high)}


def without(body, name):
    out = dict(body)
    out.pop(name)
    return out



@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("wrap", [lambda b: b, ts])
def test_edr_true_false(mode, wrap):
    v, dc, out = run("isEDRDeployed", "isEDRDeployed", wrap(agents_body([agent(1), agent(2, edr=False)])), mode)
    assert (v, dc) == (True, "success")
    assert out["transformedResponse"]["edrDeployedPercentage"] == 50
    v, dc, _ = run("isEDRDeployed", "isEDRDeployed", wrap(agents_body([agent(1, edr=False), agent(2, edr=False)])), mode)
    assert (v, dc) == (False, "success")


@pytest.mark.parametrize("mode", MODES)
def test_edr_stale_and_uninstalled_not_judged(mode):
    body = agents_body([agent(1, edr=False), agent(2, edr=True, days=40), agent(3, edr=True, uninstalled=True)])
    v, dc, out = run("isEDRDeployed", "isEDRDeployed", ts(body), mode)
    assert (v, dc) == (False, "success")
    assert out["transformedResponse"]["staleAgentCount"] == 1


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("body", [agents_body([agent(i) for i in range(10)], total=12),
                                  agents_body([agent(1)], cursor="eyJpZCI6IDF9"),
                                  agents_body([agent(1)], truncated=True),
                                  agents_body([]),
                                  {"data": [agent(1)]}] + NO_EVIDENCE)
def test_edr_partial_or_no_evidence_is_unevaluated(mode, body):
    for b in (body, ts(body)):
        v, dc, _ = run("isEDRDeployed", "isEDRDeployed", b, mode)
        assert (v, dc) == (None, "error")



@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("wrap", [lambda b: b, ts, lambda b: ts({"apiResponse": b}), lambda b: json.dumps(b)])
def test_vuln_counts(mode, wrap):
    want = {"openCriticalVulnerabilitiesCount": 7, "openHighSeverityVulnerabilitiesCount": 40,
            "overdueCriticalHighVulnerabilitiesCount": 13}
    for key in VULN:
        v, dc, out = run(key, key, wrap(counts()), mode)
        assert dc == "success"
        assert list(out["transformedResponse"])[0] == key
        assert out["transformedResponse"] == want
        assert v == want[key]
        assert out["additionalInfo"]["evaluation"]["failReasons"]


@pytest.mark.parametrize("mode", MODES)
def test_vuln_totals_as_digit_strings_and_wrapped_blocks(mode):
    body = {k: {"apiResponse": {"pagination": {"totalItems": str(v["pagination"]["totalItems"])}}}
            for k, v in counts().items()}
    for key in VULN:
        assert run(key, key, ts(body), mode)[1] == "success"


@pytest.mark.parametrize("mode", MODES)
def test_vuln_clean_tenant_reads_zero(mode):
    body = counts(all_risks=12, critical=0, high=0, overdue_critical=0, overdue_high=0)
    for key in VULN:
        v, dc, out = run(key, key, ts(body), mode)
        assert (v, dc) == (0, "success")
        assert out["additionalInfo"]["evaluation"]["passReasons"]


@pytest.mark.parametrize("mode", MODES)
def test_vuln_overdue_only_fails_its_own_key(mode):
    body = counts(critical=3, high=0, overdue_critical=0, overdue_high=0)
    assert run("overdueCriticalHighVulnerabilitiesCount", "overdueCriticalHighVulnerabilitiesCount", ts(body), mode)[:2] == (0, "success")
    assert run("openCriticalVulnerabilitiesCount", "openCriticalVulnerabilitiesCount", ts(body), mode)[:2] == (3, "success")


BAD = [counts(all_risks=0, critical=0, high=0, overdue_critical=0, overdue_high=0),  # empty: licence, not zero
       counts(all_risks=40, critical=40, high=40),                                  # severity filter ignored
       counts(critical=5, overdue_critical=6),                                      # date filter widened
       counts(high=5, overdue_high=6),
       dict(counts(), critical={"data": [], "pagination": {}}),
       dict(counts(), high={"data": []}),
       dict(counts(), allRisks={"pagination": {"totalItems": -1}}),
       dict(counts(), allRisks={"pagination": {"totalItems": True}}),
       dict(counts(), overdueHigh={"pagination": {"totalItems": "many"}}),
       dict(counts(), overdueHigh={"pagination": {"totalItems": 1.5}}),
       dict(counts(), critical={"errors": [{"code": 4000010, "title": "Validation Error"}]}),
       dict(counts(), critical={"error": True, "statusCode": 400, "message": "Bad Request"}),
       dict(counts(), high=None),
       dict(counts(), high="not json"),
       {"data": [], "pagination": {"totalItems": 5}},                                # old row-shaped input
       agents_body([agent(1)])] + [without(counts(), n) for n in counts()] + NO_EVIDENCE


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("body", BAD)
def test_vuln_partial_empty_or_wrong_body_is_unevaluated(mode, body):
    for key in VULN:
        for b in (body, ts(body)):
            v, dc, out = run(key, key, b, mode)
            assert (v, dc) == (None, "error"), (key, b)
            for k in VULN:
                assert out["transformedResponse"][k] is None
            assert out["additionalInfo"]["dataCollection"]["errors"]
