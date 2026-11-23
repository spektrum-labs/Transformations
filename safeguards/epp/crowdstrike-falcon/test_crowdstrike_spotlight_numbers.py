"""CrowdStrike Spotlight numbers: open critical, open high, overdue (BOD 19-02 windows), and isPatchManagementValid
derived from overdue == 0. All four files share one body; each emits its own key first.

No customer has ever returned a Spotlight 200 on this definition (every call so far was 403 scope or 400 "filter is
required"), so the fixture is SYNTHETIC, built to the documented combined-vulnerabilities shape (resources[] with
status, cve.severity, cve.id, aid, created_timestamp; meta.pagination {limit, total, after}) as IS merges pages.
Fail closed: null, {}, [], 401, 403, 400 "filter is required", partial page, truncated merge -> None + error."""
import copy
import importlib.util
import json
import pathlib
from datetime import datetime, timedelta

HERE = pathlib.Path(__file__).resolve().parent
KEYS = ["isPatchManagementValid", "openCriticalVulnerabilitiesCount", "openHighSeverityVulnerabilitiesCount",
        "overdueCriticalHighVulnerabilitiesCount"]
MODS = {}
for k in KEYS:
    spec = importlib.util.spec_from_file_location("cs_spot_" + k, HERE / (k + ".py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    MODS[k] = m


def ts(days_ago):
    return (datetime.utcnow() - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%S.123Z")


def rec(sev, days_ago, status="open", aid="h1", cve="CVE-2026-0001"):
    return {"id": aid + "_" + cve, "aid": aid, "cid": "c", "status": status, "created_timestamp": ts(days_ago),
            "cve": {"id": cve, "severity": sev, "base_score": 9.8}, "remediation": {"ids": ["r1"]}}


def body(records, total=None, extra=None):
    b = {"meta": {"query_time": 0.1, "powered_by": "spapi", "trace_id": "t",
                  "pagination": {"limit": 5000, "total": len(records) if total is None else total, "after": None}},
         "resources": records, "errors": []}
    if extra:
        b["meta"]["pagination"].update(extra)
    return b


FRESH = body([rec("CRITICAL", 3), rec("HIGH", 10, aid="h2", cve="CVE-2026-0002"), rec("HIGH", 29, status="reopen")])
STALE = body([rec("CRITICAL", 16), rec("CRITICAL", 2, aid="h2"), rec("HIGH", 31, cve="CVE-2026-0003"),
              rec("HIGH", 5, aid="h3")])


def run(key, b):
    out = MODS[key].transform(b)
    return out["transformedResponse"][key], out["additionalInfo"]["dataCollection"]["status"], out


def test_fresh_findings_counted_none_overdue_valid():
    assert run("openCriticalVulnerabilitiesCount", FRESH)[:2] == (1, "success")
    assert run("openHighSeverityVulnerabilitiesCount", FRESH)[:2] == (2, "success")
    assert run("overdueCriticalHighVulnerabilitiesCount", FRESH)[:2] == (0, "success")
    assert run("isPatchManagementValid", FRESH)[:2] == (True, "success")


def test_overdue_flips_valid_false():
    assert run("openCriticalVulnerabilitiesCount", STALE)[:2] == (2, "success")
    assert run("openHighSeverityVulnerabilitiesCount", STALE)[:2] == (2, "success")
    assert run("overdueCriticalHighVulnerabilitiesCount", STALE)[:2] == (2, "success")
    assert run("isPatchManagementValid", STALE)[:2] == (False, "success")


def test_every_file_emits_all_numbers():
    for k in KEYS:
        out = run(k, STALE)[2]["transformedResponse"]
        for other in KEYS:
            assert other in out, (k, other)


def test_measured_zero_from_spotlight_envelope():
    for k, v in [("openCriticalVulnerabilitiesCount", 0), ("overdueCriticalHighVulnerabilitiesCount", 0),
                 ("isPatchManagementValid", True)]:
        assert run(k, body([]))[:2] == (v, "success")


def test_closed_and_low_are_not_counted():
    b = body([rec("CRITICAL", 40, status="closed"), rec("MEDIUM", 90), rec("HIGH", 1)])
    assert run("openCriticalVulnerabilitiesCount", b)[:2] == (0, "success")
    assert run("openHighSeverityVulnerabilitiesCount", b)[:2] == (1, "success")
    assert run("isPatchManagementValid", b)[:2] == (True, "success")


def test_wrapped_and_string_inputs():
    for b in ({"apiResponse": STALE}, json.dumps(STALE), {"response": {"result": STALE}}):
        assert run("overdueCriticalHighVulnerabilitiesCount", b)[:2] == (2, "success")


NO_EVIDENCE = [
    None, {}, [], "", "null",
    {"error": True, "message": "Integration execution error: HTTP 401: Unauthorized"},
    {"errors": [{"code": 401, "message": "access denied, invalid bearer token"}], "resources": [], "meta": {}},
    {"meta": {"trace_id": "x"}, "errors": [{"code": 403, "message": "access denied, scope not permitted"}]},
    {"meta": {"query_time": 0.0003, "powered_by": "spapi", "trace_id": "x"}, "resources": None,
     "errors": [{"code": 400, "message": "filter is required"}]},
    {"resources": [], "meta": {"pagination": {"limit": 5000}}},          # no total
    {"resources": [], "meta": {"pagination": {"total": "0"}}},           # total not a number
    {"status": "Not Available", "message": "Integrator SRN x not configured"},
]


def test_no_evidence_is_unevaluated():
    for k in KEYS:
        for b in NO_EVIDENCE:
            v, status, out = run(k, b)
            assert v is None and status == "error", (k, b, v, status)


def test_partial_page_and_truncated_merge_are_unevaluated():
    partial = body(STALE["resources"], total=9000)
    trunc = body(STALE["resources"], extra={"truncated": True, "scannedCount": 4})
    for k in KEYS:
        for b in (partial, trunc):
            v, status, out = run(k, b)
            assert v is None and status == "error", (k, v)
            assert "partial read" in out["additionalInfo"]["dataCollection"]["errors"][0]


def test_unreadable_record_is_unevaluated():
    for mutate in ("status", "cve", "created_timestamp"):
        b = copy.deepcopy(STALE)
        b["resources"][0].pop(mutate)
        for k in KEYS:
            assert run(k, b)[:2] == (None, "error"), (mutate, k)
    b = copy.deepcopy(STALE)
    b["resources"][0]["created_timestamp"] = "yesterday"
    assert run("overdueCriticalHighVulnerabilitiesCount", b)[:2] == (None, "error")
