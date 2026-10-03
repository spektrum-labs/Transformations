"""CrowdStrike Spotlight checks from the vendor's own counts (the *FromSpotlightCounts.py files):
isPatchManagementValid, openCriticalVulnerabilitiesCount, openHighSeverityVulnerabilitiesCount and
overdueCriticalHighVulnerabilitiesCount for Crowdstrike - XDR Falcon (765f3eb2) and CrowdStrike Falcon-Endpoint
Security (d61a39d7).

Every body here is SYNTHETIC. It follows the documented GET /spotlight/queries/vulnerabilities/v1 shape
(meta.pagination {limit, total, after}, resources = ids, errors []) wrapped by the IS workflow
spotlightCriticalHighCounts (merge + output.key, one block per step). The totals in the "real scale" cases are the
synthetic, at the scale the record-reading files met on 2-3 Oct 2026 (about 1M and about 100k), where the 100,000-record
page cap stopped every read.

Bundle targets: the three counts are lessThan "0" (Token-Service lessThan is inclusive on int-truncated values, so 0
passes and 1 or more fails; None is never satisfied); isPatchManagementValid is equals true.
"""
import copy
import importlib.util
import json
import pathlib

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]
COUNT_KEYS = ["openCriticalVulnerabilitiesCount", "openHighSeverityVulnerabilitiesCount",
              "overdueCriticalHighVulnerabilitiesCount"]
VALID = "isPatchManagementValid"
KEYS = COUNT_KEYS + [VALID]
MODS = {}
for k in KEYS:
    spec = importlib.util.spec_from_file_location("cs_spot_counts_" + k, HERE / (k + "FromSpotlightCounts.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    MODS[k] = m


def block(total, as_strings=False, ids=None):
    if ids is None:
        ids = [] if int(total) == 0 else ["synthaid00_synthvuln%04d" % int(total)]
    pagination = {"limit": 1, "total": total, "after": "synthetic-cursor" if ids else ""}
    if as_strings:  # stored evidence renders scalars as strings
        pagination = {"limit": "1", "total": str(total), "after": str(pagination["after"])}
    return {"meta": {"query_time": 0.05, "powered_by": "spapi", "trace_id": "synthetic-trace",
                     "pagination": pagination},
            "resources": ids, "errors": []}


def composite(crit, high, over_crit, over_high, as_strings=False, combined=None):
    combined = crit + high if combined is None else combined
    return {"openCriticalHigh": block(combined, as_strings), "openCritical": block(crit, as_strings),
            "openHigh": block(high, as_strings), "overdueCritical": block(over_crit, as_strings),
            "overdueHigh": block(over_high, as_strings)}


def run(key, body):
    out = MODS[key].transform(body)
    return out["transformedResponse"][key], out["additionalInfo"]["dataCollection"]["status"], out


def satisfied(key, value):
    if value is None:
        return False
    if key == VALID:
        return value is True
    return int(value) <= 0


# ---------------------------------------------------------------- real-scale reads that the page cap used to stop

def test_real_scale_failing_estate_is_scored_not_unevaluated():
    # About 1M open critical+high instances (synthetic): the record reader stopped at 100,000 and said "partial read".
    body = composite(200_000, 800_000, 150_000, 500_000)
    want = {"openCriticalVulnerabilitiesCount": 200_000, "openHighSeverityVulnerabilitiesCount": 800_000,
            "overdueCriticalHighVulnerabilitiesCount": 650_000, VALID: False}
    for k in KEYS:
        v, status, out = run(k, body)
        assert (v, status) == (want[k], "success"), (k, v, status)
        assert not satisfied(k, v)
        assert out["additionalInfo"]["evaluation"]["failReasons"], k
        assert out["transformedResponse"]["spotlightOpenCriticalHighTotal"] == 1_000_000


def test_real_scale_as_stored_evidence_strings():
    body = composite(10_000, 100_000, 4_000, 20_000, as_strings=True)
    assert run("openHighSeverityVulnerabilitiesCount", body)[:2] == (100_000, "success")
    assert run(VALID, body)[:2] == (False, "success")
    assert run("overdueCriticalHighVulnerabilitiesCount", body)[:2] == (24_000, "success")


def test_every_file_emits_all_numbers_own_key_first():
    for k in KEYS:
        out = run(k, composite(5, 7, 1, 2))[2]["transformedResponse"]
        assert list(out)[0] == k
        for other in COUNT_KEYS + ["overdueCriticalCount", "overdueHighCount", "spotlightOpenCriticalHighTotal"]:
            assert isinstance(out[other], int) and not isinstance(out[other], bool), (k, other)
        assert (out["overdueCriticalCount"], out["overdueHighCount"]) == (1, 2)


# ---------------------------------------------------------------- flipped: the same estate, passing

def test_flipped_overdue_zero_makes_patch_management_valid():
    body = composite(5, 7, 0, 0)
    assert run(VALID, body)[:2] == (True, "success")
    v, status, out = run("overdueCriticalHighVulnerabilitiesCount", body)
    assert (v, status) == (0, "success") and satisfied("overdueCriticalHighVulnerabilitiesCount", v)
    assert out["additionalInfo"]["evaluation"]["passReasons"]
    # open counts still fail: findings inside the window are still open
    assert run("openCriticalVulnerabilitiesCount", body)[0] == 5


def test_flipped_one_overdue_high_breaks_validity():
    assert run(VALID, composite(0, 1, 0, 1))[:2] == (False, "success")
    assert run(VALID, composite(1, 0, 1, 0))[:2] == (False, "success")


def test_critical_only_and_high_only():
    assert run("openHighSeverityVulnerabilitiesCount", composite(3, 0, 0, 0))[:2] == (0, "success")
    assert run("openCriticalVulnerabilitiesCount", composite(0, 4, 0, 0))[:2] == (0, "success")


# ---------------------------------------------------------------- empty: a measured zero

def test_measured_zero_passes_every_check():
    for body in (composite(0, 0, 0, 0), composite(0, 0, 0, 0, as_strings=True)):
        for k in KEYS:
            v, status, out = run(k, body)
            assert status == "success", (k, status)
            assert satisfied(k, v), (k, v)
            assert out["additionalInfo"]["evaluation"]["passReasons"], k


def test_wrapped_string_and_bytes_inputs():
    body = composite(2, 3, 1, 1)
    wrapped_blocks = {n: {"apiResponse": b} for n, b in body.items()}
    for b in ({"apiResponse": body}, {"response": {"result": body}}, json.dumps(body), json.dumps(body).encode(),
              {"data": body, "validation": {"status": "valid", "errors": [], "warnings": []}}, wrapped_blocks):
        assert run("overdueCriticalHighVulnerabilitiesCount", b)[:2] == (2, "success")
        assert run(VALID, b)[:2] == (False, "success")


# ---------------------------------------------------------------- None, errors and anything incomplete: Unevaluated

SCOPE_403 = {"vendorErrorAsResponse": {"status": 403, "bodyContains": "scope not permitted",
                                       "body": json.dumps({"meta": {}, "resources": [], "errors": [
                                           {"code": 403, "message": "access denied, scope not permitted"}]})}}


def unevaluated_cases():
    base = composite(5, 7, 1, 2)
    cases = {
        "None": None,
        "{}": {},
        "[]": [],
        "empty string": "",
        "null string": "null",
        "empty bytes": b"",
        "not json": "not json",
        "IS error 401": {"error": True, "message": "Integration execution error: HTTP 401: Unauthorized"},
        "IS error 400 (bad FQL)": {"error": True, "statusCode": 400,
                                   "message": "Integration execution error: HTTP 400: invalid filter"},
        "not configured": {"status": "Not Available", "message": "Integrator SRN x not configured"},
        "old combined envelope (records, not counts)": {"meta": {"pagination": {"total": 0}}, "resources": [],
                                                        "errors": []},
    }
    for name in ("openCriticalHigh", "openCritical", "openHigh", "overdueCritical", "overdueHigh"):
        b = copy.deepcopy(base)
        b.pop(name)
        cases["missing block " + name] = b
        b = copy.deepcopy(base)
        b[name] = None
        cases["null block " + name] = b
    def with_block(name, value):
        b = copy.deepcopy(base)
        b[name] = value
        return b
    cases["vendor error 400 in a block"] = with_block("overdueHigh", {
        "meta": {"pagination": {"total": 0}}, "resources": [],
        "errors": [{"code": 400, "message": "Invalid filter: created_timestamp"}]})
    cases["vendor error 500 in a block"] = with_block("openHigh", {
        "meta": {}, "resources": None, "errors": [{"code": 500, "message": "internal error"}]})
    cases["IS error in a block"] = with_block("openCritical", {"error": True, "message": "HTTP 429"})
    cases["total missing"] = with_block("openCritical", {"meta": {"pagination": {"limit": 1}}, "resources": [],
                                                         "errors": []})
    cases["total null"] = with_block("openCritical", {"meta": {"pagination": {"total": None}}, "resources": [],
                                                      "errors": []})
    cases["total non-numeric"] = with_block("openHigh", {"meta": {"pagination": {"total": "abc"}}, "resources": [],
                                                         "errors": []})
    cases["total negative"] = with_block("openHigh", {"meta": {"pagination": {"total": -1}}, "resources": [],
                                                      "errors": []})
    cases["total boolean"] = with_block("overdueHigh", {"meta": {"pagination": {"total": False}}, "resources": [],
                                                        "errors": []})
    cases["total float string"] = with_block("overdueHigh", {"meta": {"pagination": {"total": "0.0"}},
                                                             "resources": [], "errors": []})
    cases["no pagination"] = with_block("openCriticalHigh", {"meta": {}, "resources": [], "errors": []})
    cases["resources not a list"] = with_block("openCriticalHigh", {"meta": {"pagination": {"total": 12}},
                                                                     "resources": None, "errors": []})
    cases["ids but total 0"] = with_block("overdueCritical", block(0, ids=["x"]))
    cases["total above 0, no ids"] = with_block("overdueCritical", block(1, ids=[]))
    cases["more ids than total"] = with_block("overdueCritical", block(1, ids=["a", "b"]))
    cases["non-string id"] = with_block("overdueCritical", block(1, ids=[7]))
    cases["severity split disagrees with combined total"] = composite(5, 7, 1, 2, combined=13)
    cases["severity filter ignored (each equals the combined)"] = composite(12, 12, 1, 2, combined=12)
    cases["overdue critical exceeds open critical"] = composite(5, 7, 6, 2)
    cases["overdue high exceeds open high"] = composite(5, 7, 1, 8)
    cases["scope 403 in a block"] = with_block("openCritical", SCOPE_403)
    cases["other refusal in a block"] = with_block("openHigh", {"vendorErrorAsResponse": {"status": 403,
                                                                                         "body": "nope"}})
    cases["scope 403 as plain errors"] = with_block("openHigh", {"meta": {}, "resources": [], "errors": [
        {"code": 403, "message": "access denied, scope not permitted"}]})
    return cases


def test_unevaluated_cases_for_every_key():
    for k in KEYS:
        for name, b in unevaluated_cases().items():
            v, status, out = run(k, b)
            assert v is None and status == "error", (k, name, v, status)
            assert all(out["transformedResponse"][x] is None for x in COUNT_KEYS), (k, name)
            assert not satisfied(k, v)
            assert out["additionalInfo"]["dataCollection"]["errors"], (k, name)


def test_scope_refusal_is_typed():
    for k in KEYS:
        out = run(k, unevaluated_cases()["scope 403 in a block"])[2]
        dc = out["additionalInfo"]["dataCollection"]
        assert dc["errorCode"] == "scope_not_granted" and dc["requiredScope"] == "Vulnerabilities: Read", k
        out = run(k, unevaluated_cases()["other refusal in a block"])[2]
        assert out["additionalInfo"]["dataCollection"]["errorCode"] == "vendor_refusal", k


def test_problem_messages_name_the_cause():
    cases = unevaluated_cases()
    msg = run(VALID, cases["missing block overdueHigh"])[2]["additionalInfo"]["dataCollection"]["errors"][0]
    assert "overdueHigh" in msg and "missing" in msg
    msg = run(VALID, cases["severity filter ignored (each equals the combined)"])[2]
    assert "disagree" in msg["additionalInfo"]["dataCollection"]["errors"][0]


def test_transformation_exception_is_unevaluated(monkeypatch):
    m = MODS[VALID]
    monkeypatch.setattr(m, "measure", lambda data: 1 / 0)
    out = m.transform(composite(1, 1, 0, 0))
    assert out["transformedResponse"][VALID] is None
    assert out["additionalInfo"]["transformation"]["status"] == "error"


# ---------------------------------------------------------------- the production sandbox

def test_every_file_compiles_and_runs_in_the_restricted_sandbox():
    import sys
    sys.path.insert(0, str(ROOT / "tools"))
    try:
        import restricted_sandbox
    except ImportError:  # RestrictedPython not installed locally; CI's contract job compiles every file
        return
    for k in KEYS:
        ns = restricted_sandbox.load((HERE / (k + "FromSpotlightCounts.py")).read_text())
        out = ns["transform"](composite(5, 7, 0, 0))
        assert out["additionalInfo"]["dataCollection"]["status"] == "success", k
        assert out["transformedResponse"][k] == (True if k == VALID else {"openCriticalVulnerabilitiesCount": 5,
                                                 "openHighSeverityVulnerabilitiesCount": 7,
                                                 "overdueCriticalHighVulnerabilitiesCount": 0}[k]), k
        bad = ns["transform"](None)
        assert bad["transformedResponse"][k] is None, k


# ---------------------------------------------------------------- an error flag on a wrapper must never be peeled away

def test_error_on_top_level_wrapper_is_unevaluated_not_a_pass():
    body = {"apiResponse": composite(0, 0, 0, 0), "error": True, "message": "upstream failure"}
    for k in KEYS:
        v, status, _ = run(k, body)
        assert v is None and status == "error", (k, v, status)


def test_errors_list_on_top_level_wrapper_is_unevaluated_not_a_pass():
    body = {"response": composite(0, 0, 0, 0), "errors": [{"code": 500, "message": "boom"}]}
    for k in KEYS:
        v, status, _ = run(k, body)
        assert v is None and status == "error", (k, v, status)


def test_error_on_block_wrapper_is_unevaluated_not_a_pass():
    body = composite(0, 0, 0, 0)
    body["openCritical"] = {"apiResponse": body["openCritical"], "error": True}
    for k in KEYS:
        v, status, _ = run(k, body)
        assert v is None and status == "error", (k, v, status)
