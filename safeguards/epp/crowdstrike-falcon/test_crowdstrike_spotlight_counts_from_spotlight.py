"""CrowdStrike XDR Falcon (765f3eb2) Spotlight counts: openCriticalVulnerabilitiesCount,
openHighSeverityVulnerabilitiesCount, overdueCriticalHighVulnerabilitiesCount (the *FromSpotlight.py files).

Every body here is SYNTHETIC, generated below. It follows the documented getCriticalVulnerabilities shape
(GET /spotlight/combined/vulnerabilities/v1, filter open/reopen + CRITICAL/HIGH, facet=cve) as IS merges the pages:
meta.pagination {limit, total, after} and resources[] with id, aid, status, created_timestamp and cve.severity.
Ids are made up and dates are relative to a fixed NOW.

The bundle target for all three keys is lessThan "0". Token-Service lessThan is inclusive (<=) on int-truncated
values, so 0 passes and 1 or more fails; None is never satisfied.

Zero rule: a response with meta.pagination.total explicitly 0, resources [] and no errors is a MEASURED zero and
passes. A missing or non-numeric total, a vendor error (400/401/403), truncated paging, a record count other than
total, a repeated id or no body is Unevaluated (None).
"""
import copy
import importlib.util
import json
import pathlib
from datetime import datetime, timedelta

HERE = pathlib.Path(__file__).resolve().parent
KEYS = ["openCriticalVulnerabilitiesCount", "openHighSeverityVulnerabilitiesCount",
        "overdueCriticalHighVulnerabilitiesCount"]
MODS = {}
for k in KEYS:
    spec = importlib.util.spec_from_file_location("cs_xdr_spot_" + k, HERE / (k + "FromSpotlight.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    MODS[k] = m

FIXED_NOW = datetime(2026, 1, 15, 12, 0, 0)

# (severity, days since first detected, status) -- made up; expected counts follow by construction.
SPEC = [
    ("CRITICAL", 3, "open"),
    ("CRITICAL", 16, "open"),     # overdue (> 15 days)
    ("CRITICAL", 40, "reopen"),   # overdue
    ("HIGH", 10, "open"),
    ("HIGH", 29, "reopen"),
    ("HIGH", 31, "open"),         # overdue (> 30 days)
    ("HIGH", 90, "open"),         # overdue
]
SPEC_CRITICAL, SPEC_HIGH, SPEC_OVERDUE = 3, 4, 4


def stamp(now, days_ago):
    return (now - timedelta(days=days_ago, hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_records(spec, now, hosts=3):
    out = []
    for i, (sev, age, status) in enumerate(spec):
        out.append({"id": "synthaid%02d_synthvuln%04d" % (i % hosts, i), "aid": "synthaid%02d" % (i % hosts),
                    "status": status, "created_timestamp": stamp(now, age), "cve": {"severity": sev}})
    return out


def make_body(records, total=None, as_strings=False):
    total = len(records) if total is None else total
    pagination = {"limit": 5000, "total": total, "after": None}
    if as_strings:  # stored evidence renders scalars as strings
        pagination = {"limit": "5000", "total": str(total), "after": "None"}
    return {"meta": {"query_time": 0.12, "powered_by": "spapi", "trace_id": "synthetic-trace",
                     "pagination": pagination},
            "resources": records, "errors": []}


def run(key, body):
    out = MODS[key].transform(body)
    return out["transformedResponse"][key], out["additionalInfo"]["dataCollection"]["status"], out


def satisfied(value, target="0"):
    if value is None:
        return False
    return int(value) <= int(float(target))


def live(spec):
    """A body dated against the current clock, for transform() (which reads utcnow)."""
    return make_body(make_records(spec, datetime.utcnow()))


# ---------------------------------------------------------------- counts and the failing body

def test_counts_at_fixed_time():
    numbers, problem = MODS[KEYS[0]].measure(make_body(make_records(SPEC, FIXED_NOW)), FIXED_NOW)
    assert problem is None
    assert numbers["openCriticalVulnerabilitiesCount"] == SPEC_CRITICAL
    assert numbers["openHighSeverityVulnerabilitiesCount"] == SPEC_HIGH
    assert numbers["overdueCriticalHighVulnerabilitiesCount"] == SPEC_OVERDUE
    assert numbers["spotlightRecordsRead"] == numbers["spotlightTotal"] == len(SPEC)
    assert numbers["hostsWithOpenCriticalOrHigh"] == 3


def test_failing_body_fails_each_check_typed_and_as_stored():
    for as_strings in (False, True):
        body = make_body(make_records(SPEC, datetime.utcnow()), as_strings=as_strings)
        for k, want in zip(KEYS, (SPEC_CRITICAL, SPEC_HIGH, SPEC_OVERDUE)):
            v, status, out = run(k, body)
            assert (v, status) == (want, "success"), (k, v, status)
            assert not satisfied(v)
            assert out["additionalInfo"]["evaluation"]["failReasons"], k


def test_every_file_emits_all_three_own_key_first():
    for k in KEYS:
        out = run(k, live(SPEC))[2]["transformedResponse"]
        assert list(out)[0] == k
        for other in KEYS:
            assert isinstance(out[other], int), (k, other)


# ---------------------------------------------------------------- passing bodies

def test_measured_zero_passes_every_check():
    for body in (make_body([], total=0), make_body([], total=0, as_strings=True)):
        for k in KEYS:
            v, status, out = run(k, body)
            assert (v, status) == (0, "success"), (k, v, status)
            assert satisfied(v)
            assert out["additionalInfo"]["evaluation"]["passReasons"], k


def test_open_critical_passes_with_high_only():
    body = live([s for s in SPEC if s[0] == "HIGH"])
    v, status, _ = run("openCriticalVulnerabilitiesCount", body)
    assert (v, status) == (0, "success") and satisfied(v)
    assert run("openHighSeverityVulnerabilitiesCount", body)[0] == SPEC_HIGH


def test_open_high_passes_with_critical_only():
    body = live([s for s in SPEC if s[0] == "CRITICAL"])
    v, status, _ = run("openHighSeverityVulnerabilitiesCount", body)
    assert (v, status) == (0, "success") and satisfied(v)


def test_overdue_passes_when_every_finding_is_inside_the_window():
    body = live([(sev, 2, status) for sev, _, status in SPEC])
    v, status, _ = run("overdueCriticalHighVulnerabilitiesCount", body)
    assert (v, status) == (0, "success") and satisfied(v)
    assert run("openCriticalVulnerabilitiesCount", body)[0] == SPEC_CRITICAL


def test_sla_boundaries_match_bod_19_02():
    m = MODS["overdueCriticalHighVulnerabilitiesCount"]
    for sev, days, expect in (("CRITICAL", 15, 0), ("CRITICAL", 16, 1), ("HIGH", 30, 0), ("HIGH", 31, 1)):
        rec = make_records([(sev, 0, "open")], FIXED_NOW)
        rec[0]["created_timestamp"] = (FIXED_NOW - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
        numbers, problem = m.measure(make_body(rec), FIXED_NOW)
        assert problem is None and numbers["overdueCriticalHighVulnerabilitiesCount"] == expect, (sev, days)


def test_closed_and_other_severities_are_not_counted():
    body = make_body(make_records([("CRITICAL", 40, "closed"), ("MEDIUM", 90, "open"), ("HIGH", 1, "open")],
                                  FIXED_NOW))
    numbers, problem = MODS[KEYS[0]].measure(body, FIXED_NOW)
    assert problem is None
    assert (numbers["openCriticalVulnerabilitiesCount"], numbers["openHighSeverityVulnerabilitiesCount"],
            numbers["overdueCriticalHighVulnerabilitiesCount"]) == (0, 1, 0)


def test_large_merged_read_is_complete():
    spec = [("CRITICAL" if i % 5 == 0 else "HIGH", i % 45, "open") for i in range(11000)]
    body = make_body(make_records(spec, FIXED_NOW, hosts=40))
    numbers, problem = MODS[KEYS[0]].measure(body, FIXED_NOW)
    assert problem is None
    assert numbers["openCriticalVulnerabilitiesCount"] == 2200
    assert numbers["openHighSeverityVulnerabilitiesCount"] == 8800


def test_wrapped_string_and_bytes_inputs():
    body = live(SPEC)
    for b in ({"apiResponse": body}, {"response": {"result": body}}, json.dumps(body), json.dumps(body).encode()):
        assert run("overdueCriticalHighVulnerabilitiesCount", b)[:2] == (SPEC_OVERDUE, "success")


# ---------------------------------------------------------------- Unevaluated, never a pass

def unevaluated_cases():
    base = make_body(make_records(SPEC, FIXED_NOW))
    cases = {
        "no body: None": None,
        "no body: {}": {},
        "no body: []": [],
        "no body: empty string": "",
        "no body: null string": "null",
        "no body: empty bytes": b"",
        "no body: not json": "not json",
        "vendor error 401 (IS)": {"error": True, "message": "Integration execution error: HTTP 401: Unauthorized"},
        "vendor error 403 (IS)": {"error": True, "message": "Integration execution error: HTTP 403: Forbidden"},
        "vendor error 403": {"meta": {"trace_id": "x"}, "resources": [],
                             "errors": [{"code": 403, "message": "access denied, scope not permitted"}]},
        "vendor error 400": {"meta": {"powered_by": "spapi"}, "resources": None,
                             "errors": [{"code": 400, "message": "filter is required"}]},
        "vendor error with total 0": {"meta": {"pagination": {"total": 0}}, "resources": [],
                                      "errors": [{"code": 500, "message": "internal error"}]},
        "not configured": {"status": "Not Available", "message": "Integrator SRN x not configured"},
        "total missing": {"resources": [], "meta": {"pagination": {"limit": 5000}}, "errors": []},
        "total null": {"resources": [], "meta": {"pagination": {"total": None}}, "errors": []},
        "total non-numeric": {"resources": [], "meta": {"pagination": {"total": "abc"}}, "errors": []},
        "total negative": {"resources": [], "meta": {"pagination": {"total": -1}}, "errors": []},
        "total boolean": {"resources": [], "meta": {"pagination": {"total": False}}, "errors": []},
        "total float string": {"resources": [], "meta": {"pagination": {"total": "0.0"}}, "errors": []},
        "no pagination": {"resources": [], "meta": {}, "errors": []},
        "resources not a list": {"resources": None, "meta": {"pagination": {"total": 0}}, "errors": []},
    }
    trunc = copy.deepcopy(base)
    trunc["meta"]["pagination"]["truncated"] = True
    cases["truncated paging"] = trunc
    trunc_str = copy.deepcopy(base)
    trunc_str["meta"]["pagination"]["truncated"] = "True"
    cases["truncated paging (string)"] = trunc_str
    trunc_top = copy.deepcopy(base)
    trunc_top["truncated"] = True
    cases["truncated merge (top level)"] = trunc_top
    cases["fewer records than total"] = make_body(make_records(SPEC, FIXED_NOW), total=len(SPEC) + 5000)
    cases["more records than total"] = make_body(make_records(SPEC, FIXED_NOW), total=len(SPEC) - 1)
    cases["records but total 0"] = make_body(make_records(SPEC, FIXED_NOW), total=0)
    repeated = copy.deepcopy(base)
    repeated["resources"][-1] = copy.deepcopy(repeated["resources"][0])
    cases["repeated id"] = repeated
    for field in ("id", "status", "cve", "created_timestamp"):
        b = copy.deepcopy(base)
        b["resources"][2].pop(field)
        cases["record without " + field] = b
    b = copy.deepcopy(base)
    b["resources"][2]["created_timestamp"] = "yesterday"
    cases["unreadable created_timestamp"] = b
    b = copy.deepcopy(base)
    b["resources"][2] = "not a record"
    cases["record not an object"] = b
    return cases


def test_unevaluated_cases_for_every_key():
    for k in KEYS:
        for name, b in unevaluated_cases().items():
            v, status, out = run(k, b)
            assert v is None and status == "error", (k, name, v, status)
            assert all(out["transformedResponse"][x] is None for x in KEYS), (k, name)
            assert not satisfied(v)
            assert out["additionalInfo"]["dataCollection"]["errors"], (k, name)


def test_only_an_explicit_total_zero_reads_zero():
    zero_like = {n: b for n, b in unevaluated_cases().items() if isinstance(b, dict) and b.get("resources") == []}
    assert len(zero_like) >= 8  # empty resources with every non-explicit total, or with errors
    for name, b in zero_like.items():
        assert run(KEYS[0], b)[0] is None, name
    assert run(KEYS[0], make_body([], total=0))[0] == 0


def test_partial_reads_say_partial():
    cases = unevaluated_cases()
    for name in ("truncated paging", "fewer records than total", "more records than total", "records but total 0"):
        msg = run(KEYS[2], cases[name])[2]["additionalInfo"]["dataCollection"]["errors"][0]
        assert "partial read" in msg, (name, msg)
    msg = run(KEYS[2], cases["repeated id"])[2]["additionalInfo"]["dataCollection"]["errors"][0]
    assert "appears twice" in msg
