"""Tracekit agent evidence (Artificial Intelligence): four criteria over Integration-Service's bundle summaries.

Fixtures are synthetic summaries in the shape src/services/tracekit_evidence.py returns for
`tracekit verify --json` (tracekit-ai 1.4.2, https://github.com/Cygnux-Labs/Tracekit/blob/main/docs/verdicts.md).
"""
import importlib.util
from pathlib import Path

import pytest

KEYS = ["isAgentEvidenceIntegrityVerified", "isAgentSignerIsolated", "isAgentEvidenceIndependentlyWitnessed",
        "isAgentPolicyEnforced"]


def load(name):
    spec = importlib.util.spec_from_file_location("tracekit_" + name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MODULES = {k: load(k) for k in KEYS}


def bundle(integrity="verified", assurance="witnessed", isolation=None, failed=None, warned=None, sha="a"):
    isolation = {"remote": 2} if isolation is None else isolation
    return {"bundleSha256": sha * 64, "verifiedAt": "2026-10-25T00:00:00Z", "verifierVersion": "1.4.2",
            "exitCode": 0 if integrity in ("verified", "open") else 1, "integrity": integrity,
            "assurance": assurance, "isolation": isolation, "runCount": sum(isolation.values()),
            "passedChecks": ["coverage", "fail-open classes", "signatures"] if integrity in ("verified", "open") else [],
            "failedChecks": failed or [], "warningChecks": warned or []}


def run(key, payload):
    out = MODULES[key].transform(payload)
    return out["transformedResponse"][key], out["additionalInfo"]["dataCollection"]["status"]


@pytest.mark.parametrize("key", KEYS)
def test_good_bundles_pass_every_criterion(key):
    good = {"bundles": [bundle(), bundle(isolation={"separate-user": 1}, assurance="witnessed+monitored", sha="b")]}
    assert run(key, good) == (True, "success")
    result = MODULES[key].transform(good)["transformedResponse"]
    assert (result["bundleCount"], result["verifiedBundleCount"], result["runCount"]) == (2, 2, 3)


@pytest.mark.parametrize("key", KEYS)
@pytest.mark.parametrize("broken", [
    bundle(integrity="failed", failed=["signatures"]),
    bundle(integrity="open"),
    bundle(integrity="unverifiable"),
    bundle(integrity="unusable", assurance="none", isolation={}),
    bundle(failed=["checkpoint"]),           # VERIFIED word with a failed line is not intact
    bundle(isolation={}),                    # a verified bundle with no run shows nothing
])
def test_one_bundle_not_intact_fails_every_criterion(key, broken):
    assert run(key, {"bundles": [bundle(), broken]}) == (False, "success")


@pytest.mark.parametrize("isolation", [{"same-user": 1}, {"unknown": 1}, {"remote": 3, "same-user": 1}])
def test_dev_or_unknown_signer_is_not_isolated(isolation):
    payload = {"bundles": [bundle(isolation=isolation)]}
    assert run("isAgentSignerIsolated", payload) == (False, "success")
    assert run("isAgentEvidenceIntegrityVerified", payload) == (True, "success")


@pytest.mark.parametrize("assurance", ["dev", "local", "none"])
def test_operator_witness_or_none_is_not_independent(assurance):
    payload = {"bundles": [bundle(assurance=assurance)]}
    assert run("isAgentEvidenceIndependentlyWitnessed", payload) == (False, "success")
    assert run("isAgentEvidenceIntegrityVerified", payload) == (True, "success")


@pytest.mark.parametrize("warning", ["policy", "held calls", "gaps", "observers", "fail-open classes", "coverage"])
def test_policy_warning_fails_policy_only(warning):
    payload = {"bundles": [bundle(warned=[warning])]}
    assert run("isAgentPolicyEnforced", payload) == (False, "success")
    assert run("isAgentEvidenceIntegrityVerified", payload) == (True, "success")


def test_unrelated_warning_does_not_fail_policy():
    assert run("isAgentPolicyEnforced", {"bundles": [bundle(warned=["keys", "tiers"])]}) == (True, "success")


@pytest.mark.parametrize("key", KEYS)
@pytest.mark.parametrize("payload", [
    {}, None, "", "not json", [], {"bundles": []}, {"bundles": "x"}, {"error": "boom"}, {"statusCode": 500},
    {"bundles": [{}]},
    {"bundles": [bundle(), dict(bundle(), integrity="VERIFIED")]},        # unknown vocabulary
    {"bundles": [dict(bundle(), runCount=5)]},                             # runs do not add up
    {"bundles": [dict(bundle(), runCount=True)]},
    {"bundles": [dict(bundle(), isolation={"remote": -1}, runCount=-1)]},
    {"bundles": [dict(bundle(), failedChecks="signatures")]},
])
def test_no_evidence_is_not_measured(key, payload):
    assert run(key, payload) == (None, "error")


@pytest.mark.parametrize("key", KEYS)
def test_wrapped_and_string_input(key):
    import json
    payload = {"response": {"bundles": [bundle()]}}
    assert run(key, payload) == (True, "success")
    assert run(key, json.dumps(payload)) == (True, "success")
    assert run(key, json.dumps(payload).encode("utf-8")) == (True, "success")


@pytest.mark.parametrize("key", KEYS)
def test_truncated_window_is_not_measured(key):
    assert run(key, {"truncated": True, "bundles": [bundle()]}) == (None, "error")
    assert run(key, {"truncated": False, "bundles": [bundle()]}) == (True, "success")


@pytest.mark.parametrize("key", KEYS)
@pytest.mark.parametrize("payload", [
    {"bundles": [bundle(warned=["held_calls"])]},                          # a name 1.4.2 never reports
    {"bundles": [bundle(failed=["Held calls"])]},
    {"bundles": [dict(bundle(), exitCode=1)]},                             # verified with a failing exit
    {"bundles": [dict(bundle(), exitCode=True)]},
    {"bundles": [dict(bundle(), passedChecks="coverage")]},
    {"bundles": [{k: v for k, v in bundle().items() if k != "passedChecks"}]},
    {"truncated": "true", "bundles": [bundle()]},
    {"truncated": 1, "bundles": [bundle()]},
])
def test_unknown_vocabulary_and_inconsistent_summaries_are_not_measured(key, payload):
    assert run(key, payload) == (None, "error")


@pytest.mark.parametrize("missing", ["coverage", "fail-open classes"])
def test_policy_needs_the_lines_every_report_carries(missing):
    b = bundle()
    b["passedChecks"] = [c for c in b["passedChecks"] if c != missing]
    assert run("isAgentPolicyEnforced", {"bundles": [b]}) == (False, "success")
    assert run("isAgentEvidenceIntegrityVerified", {"bundles": [b]}) == (True, "success")


def test_a_missing_truncated_field_is_read_as_not_truncated():
    assert run("isAgentEvidenceIntegrityVerified", {"bundles": [bundle()]}) == (True, "success")
