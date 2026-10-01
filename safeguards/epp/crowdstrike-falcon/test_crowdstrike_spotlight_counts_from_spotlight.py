"""CrowdStrike XDR Falcon (765f3eb2) Spotlight counts: openCriticalVulnerabilitiesCount,
openHighSeverityVulnerabilitiesCount, overdueCriticalHighVulnerabilitiesCount (the *FromSpotlight.py files).

REAL fixture: fixtures/spotlight_open_critical_high_real_2026-10-01.json.gz is the getCriticalVulnerabilities body
(filter open/reopen + CRITICAL/HIGH, facet=cve, IS-merged pages) captured 2026-10-01 from one production tenant,
sanitized to the fields these transforms read. It is 12148 of 12148 records (1685 critical, 10463 high), so it makes
every one of the three checks fail against the bundle's target (lessThan 0; Token-Service lessThan is inclusive,
<=, on int-truncated values, so 0 passes and 1 fails). meta.pagination values are strings there, as stored.

The PASS bodies are derived from the real records (a severity subset, or the real records re-dated to inside the
BOD 19-02 window), with `total` set to the subset size. The fail-closed battery covers null, empty, vendor errors,
missing or non-numeric total, truncated, partial, repeated record, unreadable records and an empty read (total 0).
"""
import copy
import gzip
import importlib.util
import json
import pathlib
from datetime import datetime, timedelta

HERE = pathlib.Path(__file__).resolve().parent
KEYS = ["openCriticalVulnerabilitiesCount", "openHighSeverityVulnerabilitiesCount",
        "overdueCriticalHighVulnerabilitiesCount"]
FILES = {k: HERE / (k + "FromSpotlight.py") for k in KEYS}
MODS = {}
for k in KEYS:
    spec = importlib.util.spec_from_file_location("cs_xdr_spot_" + k, FILES[k])
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    MODS[k] = m

with gzip.open(HERE / "fixtures" / "spotlight_open_critical_high_real_2026-10-01.json.gz", "rt") as fh:
    REAL = json.load(fh)
REAL.pop("_note", None)
FIXED_NOW = datetime(2026, 10, 1, 19, 0, 0)  # 15:00 ET on the capture day


def run(key, body):
    out = MODS[key].transform(body)
    return out["transformedResponse"][key], out["additionalInfo"]["dataCollection"]["status"], out


def ts_satisfied(value, target="0"):
    """Token-Service lessThan: inclusive (<=), both sides truncated to int; None is never satisfied."""
    if value is None:
        return False
    return int(value) <= int(float(target))


def subset(records):
    b = copy.deepcopy(REAL)
    b["resources"] = records
    b["meta"]["pagination"]["total"] = str(len(records))
    return b


def typed(body):
    """The runtime shape: IS hands the transform CrowdStrike's int pagination values."""
    b = copy.deepcopy(body)
    p = b["meta"]["pagination"]
    p["total"] = int(p["total"])
    p["limit"] = int(p["limit"])
    p["after"] = None
    return b


def redated(body, days_ago=1):
    b = copy.deepcopy(body)
    stamp = (datetime.utcnow() - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")
    for r in b["resources"]:
        r["created_timestamp"] = stamp
    return b


# ---------------------------------------------------------------- the real body: every check fails

def test_real_body_counts_at_fixed_time():
    numbers, problem = MODS[KEYS[0]].measure(REAL, FIXED_NOW)
    assert problem is None
    assert numbers["openCriticalVulnerabilitiesCount"] == 1685
    assert numbers["openHighSeverityVulnerabilitiesCount"] == 10463
    assert numbers["overdueCriticalHighVulnerabilitiesCount"] == 5625
    assert numbers["spotlightRecordsRead"] == numbers["spotlightTotal"] == 12148
    assert numbers["hostsWithOpenCriticalOrHigh"] == 45


def test_real_body_fails_each_check_as_stored_and_as_typed():
    for body in (REAL, typed(REAL)):
        for k in KEYS:
            v, status, out = run(k, body)
            assert status == "success", (k, out["additionalInfo"]["evaluation"])
            assert isinstance(v, int) and v > 0, (k, v)
            assert not ts_satisfied(v), (k, v)
            assert out["additionalInfo"]["evaluation"]["failReasons"], k
    # overdue only grows as the real records age
    assert run("overdueCriticalHighVulnerabilitiesCount", REAL)[0] >= 5625


def test_every_file_emits_all_three_own_key_first():
    for k in KEYS:
        out = run(k, REAL)[2]["transformedResponse"]
        assert list(out)[0] == k
        for other in KEYS:
            assert isinstance(out[other], int), (k, other)


# ---------------------------------------------------------------- derived from the real records: each check passes

def test_open_critical_passes_on_real_high_only_records():
    body = subset([r for r in REAL["resources"] if r["cve"]["severity"] == "HIGH"])
    v, status, _ = run("openCriticalVulnerabilitiesCount", body)
    assert (v, status) == (0, "success") and ts_satisfied(v)
    assert run("openHighSeverityVulnerabilitiesCount", body)[0] == 10463


def test_open_high_passes_on_real_critical_only_records():
    body = subset([r for r in REAL["resources"] if r["cve"]["severity"] == "CRITICAL"])
    v, status, _ = run("openHighSeverityVulnerabilitiesCount", body)
    assert (v, status) == (0, "success") and ts_satisfied(v)
    assert run("openCriticalVulnerabilitiesCount", body)[0] == 1685


def test_overdue_passes_when_real_records_are_inside_the_window():
    body = redated(REAL, days_ago=1)
    v, status, _ = run("overdueCriticalHighVulnerabilitiesCount", body)
    assert (v, status) == (0, "success") and ts_satisfied(v)
    assert run("openCriticalVulnerabilitiesCount", body)[0] == 1685


def test_sla_boundaries_match_bod_19_02():
    crit = [r for r in REAL["resources"] if r["cve"]["severity"] == "CRITICAL"][:1]
    high = [r for r in REAL["resources"] if r["cve"]["severity"] == "HIGH"][:1]
    m = MODS["overdueCriticalHighVulnerabilitiesCount"]
    for recs, days, expect in ((crit, 15, 0), (crit, 16, 1), (high, 30, 0), (high, 31, 1)):
        body = subset(copy.deepcopy(recs))
        body["resources"][0]["created_timestamp"] = (FIXED_NOW - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
        numbers, problem = m.measure(body, FIXED_NOW)
        assert problem is None and numbers["overdueCriticalHighVulnerabilitiesCount"] == expect, (days, expect)


def test_closed_and_other_severities_are_not_counted():
    recs = copy.deepcopy(REAL["resources"][:4])
    recs[0]["status"] = "closed"
    recs[1]["cve"]["severity"] = "MEDIUM"
    body = subset(recs)
    numbers, problem = MODS[KEYS[0]].measure(body, FIXED_NOW)
    assert problem is None
    assert numbers["openCriticalVulnerabilitiesCount"] + numbers["openHighSeverityVulnerabilitiesCount"] == 2


def test_wrapped_string_and_bytes_inputs():
    small = subset(REAL["resources"][:50])
    want = run("openHighSeverityVulnerabilitiesCount", small)[0]
    for b in ({"apiResponse": small}, {"response": {"result": small}}, json.dumps(small), json.dumps(small).encode()):
        assert run("openHighSeverityVulnerabilitiesCount", b)[:2] == (want, "success")


# ---------------------------------------------------------------- fail closed: Unevaluated, never a pass

def partial_bodies():
    partial = copy.deepcopy(REAL)
    partial["resources"] = partial["resources"][:-1]                     # 12147 of 12148
    trunc = copy.deepcopy(REAL)
    trunc["meta"]["pagination"]["truncated"] = True
    trunc_str = copy.deepcopy(REAL)
    trunc_str["meta"]["pagination"]["truncated"] = "True"
    trunc_top = typed(REAL)
    trunc_top["truncated"] = True
    repeated = copy.deepcopy(REAL)
    repeated["resources"][-1] = copy.deepcopy(repeated["resources"][0])  # same id twice, count still == total
    extra = copy.deepcopy(REAL)
    extra["resources"].append(copy.deepcopy(extra["resources"][0]))      # more records than total
    return [partial, trunc, trunc_str, trunc_top, repeated, extra]


def no_evidence_bodies():
    bodies = [
        None, {}, [], "", "null", b"", "not json",
        {"error": True, "message": "Integration execution error: HTTP 401: Unauthorized"},
        {"errors": [{"code": 401, "message": "access denied, invalid bearer token"}], "resources": [], "meta": {}},
        {"meta": {"trace_id": "x"}, "errors": [{"code": 403, "message": "access denied, scope not permitted"}]},
        {"meta": {"powered_by": "spapi"}, "resources": None, "errors": [{"code": 400, "message": "filter is required"}]},
        {"status": "Not Available", "message": "Integrator SRN x not configured"},
        {"resources": [], "meta": {"pagination": {"limit": 5000}}},               # no total
        {"resources": [], "meta": {"pagination": {"total": "abc"}}},              # total not a count
        {"resources": [], "meta": {"pagination": {"total": -1}}},
        {"resources": [], "meta": {"pagination": {"total": True}}},
        {"resources": [], "meta": {"pagination": {"total": 0}}, "errors": []},    # empty read
        {"resources": [], "meta": {"pagination": {"total": "0"}}},                # empty read, as stored
        {"resources": REAL["resources"][:3], "meta": {}},                         # no pagination
    ] + partial_bodies()
    for field in ("id", "status", "cve", "created_timestamp"):
        b = subset(copy.deepcopy(REAL["resources"][:20]))
        b["resources"][5].pop(field)
        bodies.append(b)
    b = subset(copy.deepcopy(REAL["resources"][:20]))
    b["resources"][5]["created_timestamp"] = "yesterday"
    bodies.append(b)
    b = subset(copy.deepcopy(REAL["resources"][:20]))
    b["resources"][5] = "not a record"
    bodies.append(b)
    return bodies


def test_no_evidence_is_unevaluated_for_every_key():
    for k in KEYS:
        for i, b in enumerate(no_evidence_bodies()):
            v, status, out = run(k, b)
            assert v is None and status == "error", (k, i, v, status)
            assert all(out["transformedResponse"][x] is None for x in KEYS), (k, i)
            assert not ts_satisfied(v)
            assert out["additionalInfo"]["dataCollection"]["errors"], (k, i)


def test_partial_and_truncated_reads_say_partial():
    for b in partial_bodies():
        msg = run(KEYS[2], b)[2]["additionalInfo"]["dataCollection"]["errors"][0]
        assert ("partial read" in msg) or ("appears twice" in msg), msg

