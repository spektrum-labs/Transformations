"""A scan the Integration Service could not hand over carries its reason through as `errorCode`.

The Integration Service answers a nuclei scan it has no result for as
    {"status": "error", "reason": "<code>", "message": "..."}
with reasons such as asm_scan_in_progress (a scan is still running), asm_scan_retry_backoff (the last
scan produced nothing usable, so no new scan was started), asm_scan_shared_no_result and
asm_scan_max_duration_exceeded. Every Project Discovery check used to reduce that to "Nuclei scan status:
error" and drop the reason, so a scan that was simply still running read like a broken integration.

Each transform must now:
  * leave the criterion as None (Not evaluated), never False, for a reason in the asm_scan_ family;
  * report dataCollection.status "error" with the reason as dataCollection.errorCode, so a reader can tell
    "still running" from "failed";
  * pass any other reason through as errorCode too, sanitised (lower-case letters, digits and underscores,
    at most 60 characters), and drop one that is not a plain code;
  * keep an error reply with no reason exactly as before (generic text, no errorCode);
  * never let a stray `reason` change a reply whose status is "success".

Every body is synthetic.
"""
import importlib.util
from pathlib import Path

import pytest

HERE = Path(__file__).parent

# file name -> True when a reason in the asm_scan_ family must leave the key None, which every file now does.
FILES = [
    "nuclei_transform.py",
    "criticalvulnerabilitycount.py",
    "externalassetinventorycount.py",
    "isasmenabled.py",
    "knownexploitedvulncount.py",
    "knownexploitedhighvulncount.py",
    "epsshighriskcriticalvulncount.py",
    "epsshighriskhighvulncount.py",
    "iscontinuousdiscoveryenabled_scan.py",
    "vulnerabilityscanfrequency.py",
]

PENDING_REASONS = [
    "asm_scan_in_progress",
    "asm_scan_retry_backoff",
    "asm_scan_shared_no_result",
    "asm_scan_max_duration_exceeded",
]

GENERIC = "Nuclei scan status: error"


def load(name):
    spec = importlib.util.spec_from_file_location("scan_reason_" + name[:-3], HERE / name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def reply(reason, message="ASM scan not evaluated: synthetic message"):
    body = {"status": "error", "message": message}
    if reason is not None:
        body["reason"] = reason
    return body


def run(name, body):
    out = load(name).transform(body)
    return out["transformedResponse"], out["additionalInfo"]


def collection(info):
    return info["dataCollection"]


@pytest.mark.parametrize("name", FILES)
@pytest.mark.parametrize("reason", PENDING_REASONS)
def test_a_scan_that_has_no_result_is_none_with_its_reason(name, reason):
    values, info = run(name, reply(reason))
    assert values, name
    for key, value in values.items():
        assert value is None, (name, reason, key, value)
    dc = collection(info)
    assert dc["status"] == "error", (name, reason)
    assert dc["errorCode"] == reason, (name, reason, dc)
    assert dc["errors"], (name, reason)
    assert reason in dc["errors"][0], (name, reason, dc["errors"])
    assert not dc["errors"][0].startswith(GENERIC), (name, reason, dc["errors"])


@pytest.mark.parametrize("name", FILES)
def test_the_reason_is_read_in_any_letter_case(name):
    values, info = run(name, reply("ASM_SCAN_IN_PROGRESS"))
    assert all(v is None for v in values.values()), name
    assert collection(info)["errorCode"] == "asm_scan_in_progress", name


@pytest.mark.parametrize("name", FILES)
def test_another_reason_is_passed_through_and_never_passes(name):
    values, info = run(name, reply("upstream_unavailable"))
    for key, value in values.items():
        assert value in (None, False), (name, key, value)
    dc = collection(info)
    assert dc["status"] == "error", name
    assert dc["errorCode"] == "upstream_unavailable", (name, dc)
    assert dc["errors"], name


@pytest.mark.parametrize("name", FILES)
def test_an_error_reply_with_no_reason_reads_as_before(name):
    values, info = run(name, reply(None, message="No host was scanned: of 2 domain(s), 2 unresponsive"))
    for key, value in values.items():
        assert value in (None, False), (name, key, value)
    dc = collection(info)
    assert dc["status"] == "error", name
    assert dc["errors"][0].startswith(GENERIC), (name, dc["errors"])
    assert "errorCode" not in dc, (name, dc)


@pytest.mark.parametrize("name", FILES)
@pytest.mark.parametrize("reason", [
    "<script>alert(1)</script>",
    "asm scan in progress",
    "asm-scan-in-progress",
    "x" * 61,
    "line\nbreak",
    "",
    "   ",
    None,
    7,
    ["asm_scan_in_progress"],
    {"code": "asm_scan_in_progress"},
    True,
])
def test_a_reason_that_is_not_a_plain_code_is_dropped(name, reason):
    values, info = run(name, {"status": "error", "reason": reason, "message": "synthetic"})
    for key, value in values.items():
        assert value in (None, False), (name, key, value)
    dc = collection(info)
    assert dc["status"] == "error", name
    assert "errorCode" not in dc, (name, reason, dc)
    assert dc["errors"][0].startswith(GENERIC), (name, reason, dc["errors"])
    # nothing from the hostile value is copied into the text a customer reads
    assert "<script>" not in " ".join(dc["errors"]), name


@pytest.mark.parametrize("name", FILES)
def test_a_reason_of_exactly_sixty_characters_is_kept(name):
    reason = "r" * 60
    _, info = run(name, reply(reason))
    assert collection(info)["errorCode"] == reason, name


def strip_clock(info):
    meta = dict(info.get("metadata", {}))
    meta.pop("evaluatedAt", None)
    return {**info, "metadata": meta}


def success_body():
    # A well-formed multi-domain scan: clean, complete, fresh.
    from datetime import datetime, timezone
    return {
        "status": "success",
        "primaryDomain": "example.com",
        "findings": [],
        "total": "0",
        "domainsScanned": "2",
        "totalDiscovered": "2",
        "templatesScanned": "120",
        "domainResults": [
            {"domain": "example.com", "findingsCount": 0, "status": "success"},
            {"domain": "www.example.com", "findingsCount": 0, "status": "success"},
        ],
        "errors": [],
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


@pytest.mark.parametrize("name", FILES)
def test_a_stray_reason_does_not_change_a_successful_scan(name):
    plain_values, plain_info = run(name, success_body())
    noisy_values, noisy_info = run(name, {**success_body(), "reason": "asm_scan_in_progress"})
    assert noisy_values == plain_values, name
    assert strip_clock(noisy_info) == strip_clock(plain_info), name
    assert "errorCode" not in collection(noisy_info), name


@pytest.mark.parametrize("name", FILES)
def test_a_complete_scan_is_never_labelled_with_a_reason(name):
    _, info = run(name, success_body())
    assert "errorCode" not in collection(info), name


def test_a_real_scan_failure_still_reads_as_an_error_not_a_scan_in_progress():
    # status error with a reason that is not the asm_scan_ family must not borrow the "still running" wording.
    for name in FILES:
        _, info = run(name, reply("upstream_unavailable"))
        text = " ".join(collection(info)["errors"])
        assert "still running" not in text, name
        assert "asm_scan_in_progress" not in text, name


def test_nuclei_transform_scan_in_progress_leaves_both_keys_none():
    values, info = run("nuclei_transform.py", reply("asm_scan_in_progress"))
    assert values == {"noCriticalFindings": None, "noHighFindings": None}
    assert collection(info)["errorCode"] == "asm_scan_in_progress"
