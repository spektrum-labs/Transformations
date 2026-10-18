"""CrowdStrike Spotlight transforms when the Falcon API client lacks "Vulnerabilities: Read".

Files: the three *FromSpotlight.py counts and isPatchManagementValidFromSpotlight.py (derived: overdue == 0).

CrowdStrike answers a client without the scope with HTTP 403 and
{"errors": [{"code": 403, "message": "access denied, scope not permitted"}]}. With Integration-Service's per-method
vendorErrorAsResponse rule {"status": 403, "bodyContains": "scope not permitted"}, IS hands that refusal to the
transform as {"vendorErrorAsResponse": {"status": 403, "bodyContains": ..., "body": <vendor body>}} instead of an
error. The refusal measures nothing, so every key must stay None (Unevaluated) and say which scope is missing
(dataCollection errorCode "scope_not_granted", requiredScope "Vulnerabilities: Read"). It must never read as a
measured zero, a pass or a finding.

Every body here is SYNTHETIC: made-up ids and trace ids, dates relative to the clock. No fixture file is committed.
"""
import importlib.util
import json
import pathlib
from datetime import datetime

HERE = pathlib.Path(__file__).resolve().parent
COUNT_KEYS = ["openCriticalVulnerabilitiesCount", "openHighSeverityVulnerabilitiesCount",
              "overdueCriticalHighVulnerabilitiesCount"]
DERIVED = "isPatchManagementValid"
ALL_KEYS = COUNT_KEYS + [DERIVED]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


MODS = {k: load("cs_spot_scope_" + k, k + "FromSpotlight.py") for k in ALL_KEYS}

ROOT = HERE.parents[2]
try:
    import RestrictedPython  # noqa: F401
    _sb_spec = importlib.util.spec_from_file_location("restricted_sandbox_csscope", ROOT / "tools" / "restricted_sandbox.py")
    _sandbox = importlib.util.module_from_spec(_sb_spec)
    _sb_spec.loader.exec_module(_sandbox)
    sandbox_load = _sandbox.load
except ImportError:
    # without RestrictedPython the sandbox leg runs as plain exec (CI installs requirements-test.txt, which carries
    # RestrictedPython, so CI runs the real Token-Service sandbox replica)
    def sandbox_load(code, filename):
        ns = {"__name__": "csscope_sandbox"}
        exec(compile(code, filename, "exec"), ns)
        return ns

SANDBOXED = {k: sandbox_load((HERE / (k + "FromSpotlight.py")).read_text(), "<transformation>")["transform"]
             for k in ALL_KEYS}
COUNTS_TEST = load("cs_spot_counts_test_helpers", "test_crowdstrike_spotlight_counts_from_spotlight.py")
SPEC = COUNTS_TEST.SPEC

SCOPE_BODY = {"meta": {"query_time": 0.004, "powered_by": "crowdstrike-api-gateway", "trace_id": "synthetic-trace-1"},
              "errors": [{"code": 403, "message": "access denied, scope not permitted"}]}


def handed_over(status, body, needle="scope not permitted"):
    return {"vendorErrorAsResponse": {"status": status, "bodyContains": needle, "body": body}}


def run(key, body):
    out = MODS[key].transform(body)
    return out["transformedResponse"][key], out


def collection(out):
    return out["additionalInfo"]["dataCollection"]


def scope_cases():
    marker = handed_over(403, SCOPE_BODY)
    return {
        "handed over, body object": marker,
        "handed over, body JSON text": handed_over(403, json.dumps(SCOPE_BODY)),
        "handed over, body bytes": handed_over(403, json.dumps(SCOPE_BODY).encode()),
        "handed over, code as text": handed_over(403, {"errors": [{"code": "403",
                                                                   "message": "Access denied, scope not permitted"}]}),
        "IS envelope around the marker": {"apiResponse": marker, "vendorErrorAsResponse": True},
        "nested wrappers": {"response": {"result": marker}},
        "whole input as JSON text": json.dumps(marker),
        "direct vendor 403 body (no marker)": dict(SCOPE_BODY, resources=[]),
        "marker beside a zero-looking body": dict(marker, resources=[], meta={"pagination": {"total": 0}}, errors=[]),
    }


def other_refusals():
    return {
        "403 with another message": handed_over(403, {"errors": [{"code": 403,
                                                                  "message": "access denied, authorization failed"}]}),
        "403 with no body": handed_over(403, None),
        "403 with unreadable body": handed_over(403, "<html>forbidden</html>"),
        "403 with errors not a list": handed_over(403, {"errors": "access denied, scope not permitted"}),
        "401": handed_over(401, {"errors": [{"code": 401, "message": "access denied, invalid bearer token"}]}),
        "404": handed_over(404, {"errors": [{"code": 404, "message": "not found"}]}),
        "500": handed_over(500, {"errors": [{"code": 500, "message": "internal error"}]}),
        "status says 403 but the body says 401": handed_over(403, {"errors": [{"code": 401,
                                                                               "message": "scope not permitted"}]}),
        "marker flag only": {"vendorErrorAsResponse": True},
        "marker not an object": {"vendorErrorAsResponse": "403"},
        "marker without status": {"vendorErrorAsResponse": {"body": SCOPE_BODY}},
    }


# ---------------------------------------------------------------- the missing-scope 403

def test_missing_scope_is_unevaluated_and_names_the_scope():
    for k in ALL_KEYS:
        for name, body in scope_cases().items():
            v, out = run(k, body)
            assert v is None, (k, name, v)
            assert all(out["transformedResponse"][x] is None for x in ALL_KEYS if x in out["transformedResponse"]), \
                (k, name)
            dc = collection(out)
            assert dc["status"] == "error", (k, name)
            assert dc["errorCode"] == "scope_not_granted", (k, name, dc)
            assert dc["requiredScope"] == "Vulnerabilities: Read", (k, name)
            assert dc["errors"][0].startswith("SCOPE-NOT-GRANTED:"), (k, name)
            assert "Vulnerabilities: Read" in dc["errors"][0]
            ev = out["additionalInfo"]["evaluation"]
            assert ev["passReasons"] == [], (k, name)
            assert "Vulnerabilities: Read" in ev["recommendations"][0]


def test_every_file_emits_every_count_as_none_on_missing_scope():
    for k in ALL_KEYS:
        tr = run(k, handed_over(403, SCOPE_BODY))[1]["transformedResponse"]
        assert list(tr)[0] == k
        for c in COUNT_KEYS:
            assert c in tr and tr[c] is None, (k, c)


def test_missing_scope_never_satisfies_a_target():
    for k in COUNT_KEYS:
        for name, body in scope_cases().items():
            assert not COUNTS_TEST.satisfied(run(k, body)[0]), (k, name)
    for name, body in scope_cases().items():
        assert run(DERIVED, body)[0] is not True, name


# ---------------------------------------------------------------- every other refusal

def test_other_refusals_are_unevaluated_without_the_scope_label():
    for k in ALL_KEYS:
        for name, body in other_refusals().items():
            v, out = run(k, body)
            assert v is None, (k, name, v)
            dc = collection(out)
            assert dc["status"] == "error" and dc["errors"], (k, name)
            assert dc.get("errorCode") == "vendor_refusal", (k, name, dc.get("errorCode"))
            assert "requiredScope" not in dc, (k, name)
            assert not dc["errors"][0].startswith("SCOPE-NOT-GRANTED"), (k, name)


def test_plain_errors_keep_no_error_code():
    """The pre-existing Unevaluated paths are unchanged: no errorCode is invented for them."""
    for k in ALL_KEYS:
        for name, body in COUNTS_TEST.unevaluated_cases().items():
            if name == "vendor error 403":  # CrowdStrike's own scope body, read directly
                continue
            v, out = run(k, body)
            assert v is None, (k, name)
            assert "errorCode" not in collection(out), (k, name)


def test_direct_vendor_403_scope_body_is_labelled():
    body = COUNTS_TEST.unevaluated_cases()["vendor error 403"]
    for k in ALL_KEYS:
        v, out = run(k, body)
        assert v is None and collection(out)["errorCode"] == "scope_not_granted", k


# ---------------------------------------------------------------- data still measures (derived key)

def test_derived_false_when_anything_is_overdue():
    for as_strings in (False, True):
        body = COUNTS_TEST.make_body(COUNTS_TEST.make_records(SPEC, datetime.utcnow()), as_strings=as_strings)
        v, out = run(DERIVED, body)
        assert v is False, as_strings
        tr = out["transformedResponse"]
        assert (tr["openCriticalVulnerabilitiesCount"], tr["openHighSeverityVulnerabilitiesCount"],
                tr["overdueCriticalHighVulnerabilitiesCount"]) == (COUNTS_TEST.SPEC_CRITICAL, COUNTS_TEST.SPEC_HIGH,
                                                                  COUNTS_TEST.SPEC_OVERDUE)
        assert collection(out)["status"] == "success"
        assert out["additionalInfo"]["evaluation"]["failReasons"]


def test_derived_true_inside_the_window_and_on_a_measured_zero():
    inside = COUNTS_TEST.live([(sev, 2, status) for sev, _, status in SPEC])
    v, out = run(DERIVED, inside)
    assert v is True and out["additionalInfo"]["evaluation"]["passReasons"]
    for body in (COUNTS_TEST.make_body([], total=0), COUNTS_TEST.make_body([], total=0, as_strings=True)):
        assert run(DERIVED, body)[0] is True


def test_derived_unevaluated_cases():
    for name, body in COUNTS_TEST.unevaluated_cases().items():
        v, out = run(DERIVED, body)
        assert v is None, (name, v)
        assert collection(out)["status"] == "error", name


def test_derived_agrees_with_the_overdue_count():
    for spec in (SPEC, [(sev, 2, status) for sev, _, status in SPEC], [("HIGH", 31, "open")], [("CRITICAL", 15, "open")]):
        body = COUNTS_TEST.live(spec)
        overdue = run("overdueCriticalHighVulnerabilitiesCount", body)[0]
        assert run(DERIVED, body)[0] is (overdue == 0), spec


# ---------------------------------------------------------------- the same in the Token-Service sandbox replica

def test_sandbox_labels_missing_scope_and_other_refusals():
    """The production executor has no bytearray and guards item writes; the label must survive it."""
    for k in ALL_KEYS:
        transform = SANDBOXED[k]
        for name, body in scope_cases().items():
            out = transform(body)
            dc = out["additionalInfo"]["dataCollection"]
            assert out["transformedResponse"][k] is None, (k, name)
            assert out["additionalInfo"]["transformation"]["errors"] == [], (k, name)
            assert dc["errorCode"] == "scope_not_granted" and dc["requiredScope"] == "Vulnerabilities: Read", (k, name)
        for name, body in other_refusals().items():
            out = transform(body)
            assert out["transformedResponse"][k] is None, (k, name)
            assert out["additionalInfo"]["dataCollection"].get("errorCode") == "vendor_refusal", (k, name)


def test_sandbox_still_measures():
    body = COUNTS_TEST.live(SPEC)
    zero = COUNTS_TEST.make_body([], total=0)
    assert SANDBOXED["openCriticalVulnerabilitiesCount"](body)["transformedResponse"][
        "openCriticalVulnerabilitiesCount"] == COUNTS_TEST.SPEC_CRITICAL
    assert SANDBOXED[DERIVED](body)["transformedResponse"][DERIVED] is False
    assert SANDBOXED[DERIVED](zero)["transformedResponse"][DERIVED] is True
