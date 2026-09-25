"""Mimecast isemailloggingenabled.py now also emits isEmailSecurityLoggingEnabled (Token-Service
reads transformedResponse[criteriaKey] exactly) and reports an error envelope as not measured.

Real payloads (2026-09-25, redacted): a getAccount body from a Mimecast customer with Enhanced
Logging [1061], and a getAccount 403 envelope. Real, flipped, empty, None, error."""
import copy
import importlib.util
import json
import pathlib

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("mimecast_isemailloggingenabled", HERE / "isemailloggingenabled.py")
MOD = importlib.util.module_from_spec(spec)
spec.loader.exec_module(MOD)

REAL = json.loads((HERE / "fixtures" / "getaccount_real_2026-09-25.json").read_text())
FORBIDDEN = json.loads((HERE / "fixtures" / "getaccount_403_real_2026-09-25.json").read_text())
KEYS = ("isEmailSecurityLoggingEnabled", "isEmailLoggingEnabled")


def run(body):
    out = MOD.transform(body)
    return tuple(out["transformedResponse"][k] for k in KEYS), out["additionalInfo"]["dataCollection"]["status"]


def test_real_account_with_enhanced_logging_passes_both_keys():
    assert run(REAL) == ((True, True), "success")
    assert run(json.dumps(REAL)) == ((True, True), "success")
    assert run(REAL["data"]) == ((True, True), "success")  # Token-Service may hand the bare list


def test_flipped_package_removed_fails_both_keys():
    flipped = copy.deepcopy(REAL)
    flipped["data"][0]["packages"] = [p for p in flipped["data"][0]["packages"] if "[1061]" not in p]
    assert run(flipped) == ((False, False), "success")


def test_error_envelopes_are_not_measured():
    assert run(FORBIDDEN) == ((False, False), "error")
    assert run(None) == ((False, False), "error")
    assert run({"meta": {"status": 200}, "fail": [{"errors": [{"code": "err_xdk_forbidden"}]}], "data": []}) == (
        (False, False), "error")


def test_empty_bodies_fail():
    for body in ({}, "{}", [], {"data": []}):
        values, _ = run(body)
        assert values == (False, False), body
