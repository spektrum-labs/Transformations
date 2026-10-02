"""SentinelOne (2bc425fa): isEDRDeployed from getEndpoints and the three vulnerability counts from
getApplicationRisks (GET /web/api/v2.1/application-management/risks). SYNTHETIC fixtures only.

Shapes: the IS response for GET /agents and GET /application-management/risks ({"data": [...],
"pagination": {"totalItems", "nextCursor"}}), bare and inside the Token-Service envelope. Each case runs as plain
Python and in the Token-Service sandbox replica.
"""
import copy
import importlib.util
import pathlib
from datetime import datetime, timedelta

import pytest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]

TAG = "s1atlas"
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


def risk(endpoint, cve, severity, days, status="to_be_patched"):
    return {"id": endpoint + cve, "cveId": cve, "severity": severity, "endpointId": endpoint,
            "endpointName": "host-" + endpoint, "detectionDate": iso(days), "mitigationStatus": status,
            "applicationName": "SyntheticApp", "daysDetected": days}


def risks_body(rows, total=None, cursor=None, truncated=None):
    pag = {"totalItems": len(rows) if total is None else total, "nextCursor": cursor}
    if truncated is not None:
        pag["truncated"] = truncated
    return {"data": rows, "pagination": pag}


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
@pytest.mark.parametrize("wrap", [lambda b: b, ts])
def test_vuln_counts(mode, wrap):
    rows = [risk("e1", "CVE-2026-0001", "CRITICAL", 20), risk("e1", "CVE-2026-0001", "CRITICAL", 5),
            risk("e2", "CVE-2026-0001", "Critical", 3), risk("e1", "CVE-2026-0002", "HIGH", 40),
            risk("e2", "CVE-2026-0003", "High", 10), risk("e3", "CVE-2026-0004", "MEDIUM", 99),
            risk("e3", "CVE-2026-0005", "CRITICAL", 50, status="patched")]
    want = {"openCriticalVulnerabilitiesCount": 2, "openHighSeverityVulnerabilitiesCount": 2,
            "overdueCriticalHighVulnerabilitiesCount": 2}
    for key in VULN:
        v, dc, out = run(key, key, wrap(risks_body(rows)), mode)
        assert dc == "success"
        assert list(out["transformedResponse"])[0] == key
        assert out["transformedResponse"] == {**out["transformedResponse"], **want}
        assert v == want[key]


@pytest.mark.parametrize("mode", MODES)
def test_vuln_clean_tenant_reads_zero(mode):
    rows = [risk("e1", "CVE-2026-0010", "LOW", 3), risk("e2", "CVE-2026-0011", "MEDIUM", 90)]
    for key in VULN:
        assert run(key, key, ts(risks_body(rows)), mode)[:2] == (0, "success")


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("body", [risks_body([]),
                                  risks_body([risk("e1", "CVE-1", "HIGH", 1)], total=2),
                                  risks_body([risk("e1", "CVE-1", "HIGH", 1)], cursor="abc"),
                                  risks_body([risk("e1", "CVE-1", "HIGH", 1)], truncated=True),
                                  risks_body([{"cveId": "CVE-1", "endpointId": "e1", "detectionDate": iso(1)}]),
                                  risks_body([{"cveId": "CVE-1", "severity": "HIGH", "detectionDate": iso(1)}]),
                                  risks_body([{"cveId": "CVE-1", "severity": "HIGH", "endpointId": "e1", "detectionDate": "soon"}]),
                                  {"data": [risk("e1", "CVE-1", "HIGH", 1)]},
                                  agents_body([agent(1)])] + NO_EVIDENCE)
def test_vuln_partial_empty_or_wrong_body_is_unevaluated(mode, body):
    for key in VULN:
        for b in (body, ts(body)):
            v, dc, out = run(key, key, b, mode)
            assert (v, dc) == (None, "error"), (key, b)
            for k in VULN:
                assert out["transformedResponse"][k] is None
