"""PHP2Shell (CVE-2026-109618, CVE-2026-109619) exposure from CrowdStrike Falcon Spotlight: isFreeOfPHP2ShellFindings.

The contract these tests pin (True = clean, False = exposed, None = not evaluated):
- an open or reopened Spotlight record for either CVE is Exposed (False), suppressed or not, and even when the rest
  of the read is incomplete; php2shellRiskLevel is "high" when any affected asset is marked internet-facing
  (internet_exposure Yes), "standard" when every one is marked No, else "unknown";
- True only from a whole, recent, credentialed read with zero open findings: total matches the records, nothing
  truncated or repeated, every record for one of the two CVEs, at least one record (an empty answer cannot show the
  PHP2Shell detections reached the tenant), every record updated on or after 21 Oct 2026, none expired, and every
  record on a Falcon-sensor asset (managed_by "Falcon sensor");
- everything else is Not evaluated: None with dataCollection.status "error", never True. A missing-scope refusal
  names the scope.
- the file compiles and answers the same in the production sandbox replica (tools/restricted_sandbox.py).

Every body here is SYNTHETIC: made-up record ids, agent ids and host names. The two CVE ids are the published ones.
"""
import copy
import importlib.util
import json
import pathlib

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]
FILE = "isFreeOfPHP2ShellFindings.py"
KEY = "isFreeOfPHP2ShellFindings"
RISK = "php2shellRiskLevel"
VERDICT = "php2shellVerdict"
CVE_A = "CVE-2026-109618"
CVE_B = "CVE-2026-109619"
AFTER = "2026-10-22T08:15:00Z"
BEFORE = "2026-10-20T23:59:00Z"


def load():
    spec = importlib.util.spec_from_file_location("cs_php2shell", HERE / FILE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MOD = load()

try:
    import RestrictedPython  # noqa: F401
    _sb_spec = importlib.util.spec_from_file_location("restricted_sandbox_php2shell",
                                                      ROOT / "tools" / "restricted_sandbox.py")
    _sandbox = importlib.util.module_from_spec(_sb_spec)
    _sb_spec.loader.exec_module(_sandbox)
    sandbox_load = _sandbox.load
except ImportError:
    # CI installs requirements-test.txt, which carries RestrictedPython, so CI runs the real sandbox replica.
    def sandbox_load(code, filename):
        ns = {"__name__": "php2shell_sandbox"}
        exec(compile(code, filename, "exec"), ns)
        return ns

SANDBOXED = sandbox_load((HERE / FILE).read_text(), "<transformation>")["transform"]


def rec(n, cve=CVE_A, status="closed", updated=AFTER, managed="Falcon sensor", exposure="No"):
    host = {"hostname": "host-%02d" % n, "platform": "Linux"}
    if managed is not None:
        host["managed_by"] = managed
    if exposure is not None:
        host["internet_exposure"] = exposure
    return {"id": "rec-%04d" % n, "aid": "a%031d" % n, "cid": "c" * 32, "status": status,
            "created_timestamp": "2026-10-21T18:00:00Z", "updated_timestamp": updated,
            "cve": {"id": cve, "severity": "CRITICAL", "base_score": 9.2}, "host_info": host}


def body(records, total=None, truncated=False):
    pagination = {"offset": "", "limit": 5000, "total": len(records) if total is None else total}
    if truncated:
        pagination["truncated"] = True
    return {"resources": list(records), "meta": {"query_time": 0.01, "trace_id": "synthetic-trace",
                                                 "pagination": pagination}, "errors": []}


def run(payload):
    out = MOD.transform(copy.deepcopy(payload))
    return out["transformedResponse"][KEY], out


def collection(out):
    return out["additionalInfo"]["dataCollection"]


def assert_not_evaluated(payload, name=""):
    value, out = run(payload)
    assert value is None, (name, value)
    assert collection(out)["status"] == "error", name
    assert out["transformedResponse"][VERDICT] == "Not evaluated", name
    assert out["additionalInfo"]["evaluation"]["passReasons"] == [], name
    return out


# ---------------------------------------------------------------- exposed

def test_open_finding_is_exposed_with_standard_risk_when_not_internet_facing():
    value, out = run(body([rec(1, status="open"), rec(2, status="closed")]))
    tr = out["transformedResponse"]
    assert value is False
    assert tr[VERDICT] == "Exposed"
    assert tr[RISK] == "standard"
    assert tr["php2shellOpenFindings"] == 1 and tr["php2shellAffectedAssets"] == 1
    assert tr["php2shellOpenCves"] == [CVE_A]
    assert collection(out)["status"] == "success"
    assert out["additionalInfo"]["evaluation"]["recommendations"]


def test_internet_facing_asset_raises_risk_to_high():
    value, out = run(body([rec(1, status="open", exposure="No"), rec(2, cve=CVE_B, status="reopen", exposure="Yes")]))
    tr = out["transformedResponse"]
    assert value is False and tr[RISK] == "high"
    assert tr["php2shellInternetFacingAssets"] == 1
    assert tr["php2shellOpenCves"] == [CVE_A, CVE_B]


def test_unknown_internet_exposure_leaves_risk_unknown():
    for exposure in ("Pending", None, ""):
        value, out = run(body([rec(1, status="open", exposure=exposure)]))
        assert value is False, exposure
        assert out["transformedResponse"][RISK] == "unknown", exposure


def test_reopened_and_suppressed_findings_still_count():
    suppressed = rec(1, status="open")
    suppressed["suppression_info"] = {"is_suppressed": True, "reason": "ACCEPT_RISK"}
    for record in (rec(2, status="reopen"), suppressed, rec(3, status="OPEN")):
        assert run(body([record]))[0] is False


def test_a_finding_counts_even_when_the_read_is_incomplete_or_stale():
    for payload in (body([rec(1, status="open")], total=3), body([rec(1, status="open")], truncated=True),
                    body([rec(1, status="open", updated=BEFORE)]), body([rec(1, status="open", managed="Unmanaged")]),
                    {"resources": [rec(1, status="open")]}):
        value, out = run(payload)
        assert value is False
        assert out["transformedResponse"][VERDICT] == "Exposed"


def test_repeated_open_record_is_counted_once():
    tr = run(body([rec(1, status="open"), rec(1, status="open")], total=2))[1]["transformedResponse"]
    assert tr["php2shellOpenFindings"] == 1


def test_open_record_for_another_cve_is_not_a_php2shell_finding():
    out = assert_not_evaluated(body([rec(1, cve="CVE-2024-0001", status="open")]))
    assert "filter" in collection(out)["errors"][0]


# ---------------------------------------------------------------- clean

def test_whole_recent_sensor_read_with_only_closed_records_is_clean():
    value, out = run(body([rec(1), rec(2, cve=CVE_B)]))
    tr = out["transformedResponse"]
    assert value is True
    assert tr[VERDICT] == "Not exposed" and tr[RISK] == "none"
    assert tr["php2shellOpenFindings"] == 0 and tr["php2shellRecordsRead"] == 2 and tr["php2shellRecordsTotal"] == 2
    assert collection(out)["status"] == "success"
    assert out["additionalInfo"]["evaluation"]["passReasons"]


def test_total_as_digit_string_is_read():
    assert run(body([rec(1)], total="1"))[0] is True


# ---------------------------------------------------------------- not evaluated: coverage and recency

def test_empty_read_is_not_evaluated_not_clean():
    for payload in (body([]), body([], total="0")):
        out = assert_not_evaluated(payload)
        assert "no record" in collection(out)["errors"][0]


def test_expired_record_is_not_evaluated():
    assert_not_evaluated(body([rec(1), rec(2, status="expired")]))


def test_record_not_updated_since_publication_is_not_evaluated():
    assert_not_evaluated(body([rec(1), rec(2, updated=BEFORE)]))


def test_unmanaged_or_unknown_coverage_is_not_evaluated():
    for managed in ("Unmanaged", None, ""):
        out = assert_not_evaluated(body([rec(1), rec(2, managed=managed)]), managed)
        assert "Falcon sensor" in collection(out)["errors"][0]


def test_unknown_status_is_not_evaluated():
    assert_not_evaluated(body([rec(1, status="pending")]))


# ---------------------------------------------------------------- not evaluated: incomplete reads

def test_partial_capped_or_inconsistent_reads_are_not_evaluated():
    no_id = rec(2)
    del no_id["id"]
    bad_stamp = rec(3, updated="yesterday")
    cases = {
        "fewer records than total": body([rec(1)], total=2),
        "more records than total": body([rec(1), rec(2)], total=1),
        "truncated by the page cap": body([rec(1)], truncated=True),
        "envelope paginationTruncated": dict(body([rec(1)]), paginationTruncated=True),
        "truncated flag on meta": dict(body([rec(1)]), meta={"pagination": {"total": 1}, "truncated": "true"}),
        "total missing": dict(body([rec(1)]), meta={"pagination": {}}),
        "total null": dict(body([rec(1)]), meta={"pagination": {"total": None}}),
        "total negative": body([rec(1)], total=-1),
        "total a bool": body([rec(1)], total=True),
        "no meta": {"resources": [rec(1)]},
        "resources not a list": dict(body([rec(1)]), resources={"rec-0001": rec(1)}),
        "repeated record": body([rec(1), rec(1)], total=2),
        "record without id": body([rec(1), no_id]),
        "unreadable timestamp": body([rec(1), bad_stamp]),
        "record not an object": body([rec(1), "rec-0002"]),
    }
    for name, payload in cases.items():
        assert_not_evaluated(payload, name)


def test_error_bodies_are_not_evaluated():
    cases = {
        "vendor errors beside records": dict(body([rec(1)]), errors=[{"code": 500, "message": "internal error"}]),
        "IS error marker": {"error": True, "message": "Read timed out"},
        "IS error beside an empty list": dict(body([]), error="upstream failure"),
    }
    for name, payload in cases.items():
        assert_not_evaluated(payload, name)


def test_no_evidence_bodies_are_not_evaluated():
    for payload in ({}, None, "", "not json", b"", [], 0, {"resources": []}, {"meta": {"pagination": {"total": 0}}},
                    {"apiResponse": {}}, {"data": {}, "validation": {"status": "unknown"}}):
        assert_not_evaluated(payload, repr(payload)[:40])


# ---------------------------------------------------------------- refusals

def handed_over(status, payload):
    return {"vendorErrorAsResponse": {"status": status, "bodyContains": "scope not permitted", "body": payload}}


def test_missing_scope_is_not_evaluated_and_names_the_scope():
    scope_body = {"meta": {"trace_id": "synthetic"}, "errors": [{"code": 403,
                                                                  "message": "access denied, scope not permitted"}]}
    for payload in (handed_over(403, scope_body), handed_over(403, json.dumps(scope_body)), scope_body,
                    {"apiResponse": handed_over(403, scope_body)}):
        out = assert_not_evaluated(payload)
        assert collection(out)["errorCode"] == "scope_not_granted"
        assert collection(out)["requiredScope"] == "Vulnerabilities: Read"


def test_other_refusals_are_not_evaluated():
    for status in (401, 403, 404, 429, 500):
        out = assert_not_evaluated(handed_over(status, {"errors": [{"code": status, "message": "denied"}]}))
        assert collection(out)["errorCode"] == "vendor_refusal"


# ---------------------------------------------------------------- input forms and the sandbox

def test_input_forms_agree():
    clean = body([rec(1)])
    exposed = body([rec(1, status="open", exposure="Yes")])
    for payload, expected in ((clean, True), (exposed, False)):
        for form in (payload, json.dumps(payload), json.dumps(payload).encode("utf-8"), {"apiResponse": payload},
                     {"response": {"result": payload}}, {"data": payload, "validation": {"status": "valid"}}):
            assert run(form)[0] is expected, (expected, type(form))


def test_poisoned_body_is_not_evaluated():
    class Poison(dict):
        def __getitem__(self, key):
            raise RuntimeError("poisoned")

        def get(self, *args):
            raise RuntimeError("poisoned")

        def __contains__(self, key):
            raise RuntimeError("poisoned")

    out = MOD.transform(Poison())
    assert out["transformedResponse"][KEY] is None
    assert collection(out)["status"] == "error"


def test_sandbox_agrees_with_plain_import():
    payloads = [body([rec(1)]), body([rec(1, status="open", exposure="Yes")]), body([rec(1, status="reopen")]),
                body([]), body([rec(1, status="expired")]), body([rec(1, managed="Unmanaged")]),
                body([rec(1)], total=2), handed_over(403, {"errors": [{"code": 403,
                                                                       "message": "access denied, scope not permitted"}]}),
                {}, None]
    for payload in payloads:
        plain = MOD.transform(copy.deepcopy(payload))["transformedResponse"]
        boxed = SANDBOXED(copy.deepcopy(payload))["transformedResponse"]
        assert plain == boxed, payload


def test_every_answer_carries_the_criterion_and_its_supporting_fields():
    for payload in (body([rec(1)]), body([rec(1, status="open")]), body([]), {}):
        tr = run(payload)[1]["transformedResponse"]
        assert list(tr)[0] == KEY
        assert RISK in tr and VERDICT in tr and "php2shellOpenFindings" in tr
