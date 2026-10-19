"""A scan the Integration Service could not hand over carries its reason through as `errorCode`.

The Integration Service answers a nuclei scan it has no result for as
    {"status": "error", "reason": "<code>", "message": "..."}
with reasons such as asm_scan_in_progress (a scan is still running), asm_scan_retry_backoff (the last
scan produced nothing usable, so no new scan was started), asm_scan_shared_no_result and
asm_scan_max_duration_exceeded. Every Project Discovery check used to reduce that to "Nuclei scan status:
error" and drop the reason, so a scan that was simply still running read like a broken integration.

Each transform must now:
  * leave the criterion as None (Not evaluated), never False, whenever dataCollection carries an error: any
    reason, no reason, a malformed reason, an input that failed validation, a scan with zero or failed hosts,
    and an exception inside the transform;
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
def test_another_reason_is_passed_through_and_is_not_evaluated(name):
    values, info = run(name, reply("upstream_unavailable"))
    assert values, name
    for key, value in values.items():
        assert value is None, (name, key, value)
    dc = collection(info)
    assert dc["status"] == "error", name
    assert dc["errorCode"] == "upstream_unavailable", (name, dc)
    assert dc["errors"], name


@pytest.mark.parametrize("name", FILES)
def test_an_error_reply_with_no_reason_reads_as_before(name):
    values, info = run(name, reply(None, message="No host was scanned: of 2 domain(s), 2 unresponsive"))
    assert values, name
    for key, value in values.items():
        assert value is None, (name, key, value)
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
    assert values, name
    for key, value in values.items():
        assert value is None, (name, key, value)
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


# -- every error path is None with api_errors, never False --------------------------------------------------


class Poisoned(dict):
    """A non-empty object whose reads raise: it drives a transform down its except path."""

    def __init__(self):
        super().__init__(poisoned=True)

    def get(self, *args, **kwargs):
        raise RuntimeError("poisoned read")

    def __getitem__(self, key):
        raise RuntimeError("poisoned read")


def assert_not_evaluated(name, values, info, where):
    assert values, (name, where)
    for key, value in values.items():
        assert value is None, (name, where, key, value)
    dc = collection(info)
    assert dc["status"] == "error", (name, where)
    assert dc["errors"], (name, where)


@pytest.mark.parametrize("name", FILES)
def test_input_that_failed_validation_is_none_with_an_error(name):
    body = {"data": success_body(), "validation": {"status": "failed", "errors": ["synthetic"], "warnings": []}}
    values, info = run(name, body)
    assert_not_evaluated(name, values, info, "validation failed")


@pytest.mark.parametrize("name", FILES)
def test_an_exception_inside_the_transform_is_none_with_an_error(name):
    values, info = run(name, Poisoned())
    assert_not_evaluated(name, values, info, "exception")
    assert info["transformation"]["status"] == "error", name


NOT_A_SCAN = [[], "[]", "null", {}, {"status": "success"}, {"status": ["error"]}]
# A bare {"status": "success"} carries no counts at all; nuclei_transform has always read that as a scan with
# no findings (it only doubts a scan whose own counts say it scanned nothing), and that is not changed here.
NOT_A_SCAN_CASES = [(name, body) for name in FILES for body in NOT_A_SCAN
                    if not (name == "nuclei_transform.py" and body == {"status": "success"})]


@pytest.mark.parametrize("name,body", NOT_A_SCAN_CASES)
def test_a_body_that_is_not_a_scan_is_none_with_an_error(name, body):
    values, info = run(name, body)
    assert_not_evaluated(name, values, info, repr(body))


def test_nuclei_zero_hosts_scanned_is_none():
    values, info = run("nuclei_transform.py", {**success_body(), "domainsScanned": "0", "domainResults": []})
    assert values == {"noCriticalFindings": None, "noHighFindings": None}
    assert collection(info)["status"] == "error"


def test_nuclei_a_failed_host_is_none():
    results = [{"domain": "example.com", "findingsCount": 0, "status": "success"},
               {"domain": "www.example.com", "findingsCount": 0, "status": "error"}]
    values, info = run("nuclei_transform.py", {**success_body(), "domainResults": results})
    assert values == {"noCriticalFindings": None, "noHighFindings": None}
    assert collection(info)["status"] == "error"


def test_nuclei_a_scan_error_entry_is_none():
    values, info = run("nuclei_transform.py", {**success_body(), "errors": [{"domain": "example.com", "error": "x"}]})
    assert values == {"noCriticalFindings": None, "noHighFindings": None}
    assert collection(info)["status"] == "error"



@pytest.mark.parametrize("partial", [
    {"domainResults": [{"domain": "example.com", "findingsCount": 1, "status": "success"},
                       {"domain": "www.example.com", "findingsCount": 0, "status": "error"}]},
    {"errors": [{"domain": "www.example.com", "error": "x"}]},
])
def test_nuclei_a_finding_seen_on_a_partial_scan_still_fails_its_key(partial):
    # A failed host can hide findings (so a clean key is unknown), but it cannot remove a finding actually seen.
    crit = {"info": {"severity": "critical", "name": "Synthetic finding"}, "matched-at": "https://example.com/x"}
    high = {"info": {"severity": "high", "name": "Synthetic finding"}, "matched-at": "https://example.com/y"}
    values, info = run("nuclei_transform.py", {**success_body(), **partial, "total": "1", "findings": [crit]})
    assert values == {"noCriticalFindings": False, "noHighFindings": None}
    assert collection(info)["status"] == "error"
    values, info = run("nuclei_transform.py", {**success_body(), **partial, "total": "2", "findings": [crit, high]})
    assert values == {"noCriticalFindings": False, "noHighFindings": False}
    values, info = run("nuclei_transform.py", {**success_body(), **partial, "total": "1", "findings": [high]})
    assert values == {"noCriticalFindings": None, "noHighFindings": False}

def test_nuclei_findings_still_fail_and_a_clean_scan_still_passes():
    clean, clean_info = run("nuclei_transform.py", success_body())
    assert clean["noCriticalFindings"] is True and clean["noHighFindings"] is True
    assert collection(clean_info)["status"] == "success"
    found, found_info = run("nuclei_transform.py", {**success_body(), "total": "1", "findings": [
        {"info": {"severity": "critical", "name": "Synthetic finding"}, "matched-at": "https://example.com/x"}]})
    assert found["noCriticalFindings"] is False
    assert found["noHighFindings"] is True
    assert collection(found_info)["status"] == "success"


def stamp(hours_ago):
    from datetime import datetime, timedelta, timezone
    return (datetime.now(timezone.utc) - timedelta(hours=hours_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


DISCOVERY = "iscontinuousdiscoveryenabled_scan.py"


def discovery_body(**overrides):
    # a completed scan that did discover a host beyond the seed
    return {**success_body(), **overrides}


KEY = "isContinuousDiscoveryEnabled"
SEED_ONLY = dict(
    domainsScanned="1", totalDiscovered="1",
    domainResults=[{"domain": "example.com", "findingsCount": 0, "status": "success"}])


def assert_graded_false(values, info, where):
    """A measured False: graded, with its reason as a fail reason and no error on the data collection."""
    assert values == {KEY: False}, (where, values)
    assert collection(info)["status"] == "success", where
    assert collection(info)["errors"] == [], where
    assert info["transformation"]["status"] == "success", where
    assert info["evaluation"]["failReasons"], where


def assert_not_evaluated_with_error(values, info, where):
    assert values == {KEY: None}, (where, values)
    assert collection(info)["status"] == "error", where
    assert collection(info)["errors"], where
    assert info["evaluation"]["failReasons"], where


# Case 1: a completed scan, counts that agree, no host beyond the seed, nothing wrong anywhere: a proven negative.
def test_discovery_a_completed_scan_with_no_host_beyond_the_seed_is_none_with_its_error():
    # IS swallows a subfinder error or timeout into an empty list with no error recorded, so a seed-only body
    # cannot tell "found nothing" from "discovery failed": Not evaluated, never a graded False.
    values, info = run(DISCOVERY, discovery_body(timestamp=stamp(1), **SEED_ONLY))
    assert_not_evaluated_with_error(values, info, "seed only")
    assert any("beyond the seed" in r for r in collection(info)["errors"])


def test_discovery_the_seed_listed_twice_is_none_with_its_error():
    values, info = run(DISCOVERY, discovery_body(
        timestamp=stamp(1), domainsScanned="2", totalDiscovered="2",
        domainResults=[{"domain": "example.com", "findingsCount": 0, "status": "success"},
                       {"domain": "EXAMPLE.com.", "findingsCount": 0, "status": "success"}]))
    assert_not_evaluated_with_error(values, info, "seed twice")


@pytest.mark.parametrize("error", [
    {"errors": [{"domain": "example.com", "error": "subfinder timed out"}]},
    {"errors": ["discovery call failed"]},
    {"domainResults": [{"domain": "example.com", "findingsCount": 0, "status": "error"}]},
])
def test_discovery_completed_no_extra_host_but_an_error_on_the_discovery_call_is_none_with_its_error(error):
    values, info = run(DISCOVERY, discovery_body(timestamp=stamp(1), **{**SEED_ONLY, **error}))
    assert_not_evaluated_with_error(values, info, error)


@pytest.mark.parametrize("partial", [
    # the time limit stopped the fan-out: only the seed finished, 40 hosts were discovered
    dict(domainsScanned="1", totalDiscovered="40", domainsCapped=True, scanTimeLimited=True,
         domainResults=[{"domain": "example.com", "findingsCount": 0, "status": "success"}]),
    dict(domainsScanned="1", totalDiscovered="40", domainsCapped=True,
         domainResults=[{"domain": "example.com", "findingsCount": 0, "status": "success"}]),
    dict(domainsScanned="1", totalDiscovered="1", scanTimeLimited="true",
         domainResults=[{"domain": "example.com", "findingsCount": 0, "status": "success"}]),
])
def test_discovery_a_partial_scan_naming_no_host_beyond_the_seed_is_none(partial):
    values, info = run(DISCOVERY, discovery_body(timestamp=stamp(1), **partial))
    assert_not_evaluated_with_error(values, info, partial)


def test_discovery_a_time_limited_partial_that_names_a_discovered_host_still_passes():
    values, info = run(DISCOVERY, discovery_body(
        timestamp=stamp(1), domainsScanned="2", totalDiscovered="40", domainsCapped=True, scanTimeLimited=True))
    assert values[KEY] is True
    assert collection(info)["status"] == "success"


# Case 2: a readable timestamp older than the window. The scan is complete and consistent, so its own date proves
# discovery has not run in the last 48 hours: a graded False, like case 1.
@pytest.mark.parametrize("hours", [49, 200, 24 * 400])
def test_discovery_a_readable_stale_timestamp_is_a_graded_false(hours):
    values, info = run(DISCOVERY, discovery_body(timestamp=stamp(hours)))
    assert_graded_false(values, info, hours)
    assert any("not from this evaluation" in r for r in info["evaluation"]["failReasons"])


def test_discovery_a_stale_scan_with_an_error_on_the_discovery_call_is_none_with_its_error():
    values, info = run(DISCOVERY, discovery_body(
        timestamp=stamp(200), errors=[{"domain": "example.com", "error": "subfinder timed out"}]))
    assert_not_evaluated_with_error(values, info, "stale with error")


def test_discovery_the_window_edges():
    fresh, fresh_info = run(DISCOVERY, discovery_body(timestamp=stamp(47)))
    assert fresh[KEY] is True and collection(fresh_info)["status"] == "success"
    stale, stale_info = run(DISCOVERY, discovery_body(timestamp=stamp(49)))
    assert_graded_false(stale, stale_info, "49 h")


# Case 3: a missing or garbage timestamp cannot place the scan in the window: None. A future one is garbage.
def test_discovery_a_missing_timestamp_is_none_with_its_error():
    for case in ("absent", "empty", "none", "blank"):
        body = discovery_body()
        if case == "absent":
            del body["timestamp"]
        else:
            body["timestamp"] = {"empty": "", "none": None, "blank": "   "}[case]
        values, info = run(DISCOVERY, body)
        assert_not_evaluated_with_error(values, info, case)


@pytest.mark.parametrize("garbage", ["yesterday", "not a date", "2026-13-45T00:00:00Z", 12345, ["2026-10-12"], {"a": 1}])
def test_discovery_a_garbage_timestamp_is_none_with_its_error(garbage):
    values, info = run(DISCOVERY, discovery_body(timestamp=garbage))
    assert_not_evaluated_with_error(values, info, garbage)


@pytest.mark.parametrize("hours_ahead", [2, 48, 24 * 30])
def test_discovery_a_future_timestamp_is_none_with_its_error(hours_ahead):
    values, info = run(DISCOVERY, discovery_body(timestamp=stamp(-hours_ahead)))
    assert_not_evaluated_with_error(values, info, hours_ahead)


def test_discovery_a_timestamp_a_few_minutes_ahead_is_clock_skew_and_still_passes():
    values, info = run(DISCOVERY, discovery_body(timestamp=stamp(-0.5)))
    assert values[KEY] is True
    assert collection(info)["status"] == "success"


def test_discovery_a_scan_with_no_host_beyond_the_seed_and_no_timestamp_is_none():
    values, info = run(DISCOVERY, discovery_body(timestamp="", **SEED_ONLY))
    assert_not_evaluated_with_error(values, info, "seed only, untimed")


# Case 4: unchanged. An incomplete scan, or counts that disagree with the per-host results, is None.
@pytest.mark.parametrize("disagree", [
    dict(domainsScanned="5"),
    dict(totalDiscovered="1"),
    dict(totalDiscovered=None),
    dict(domainResults=[{"domain": "example.com", "findingsCount": 0, "status": "success"}]),
    dict(domainResults=None),
    dict(primaryDomain=None),
])
def test_discovery_counts_that_disagree_with_the_per_host_results_are_none(disagree):
    for extra in ({}, {"timestamp": stamp(200)}, {"timestamp": ""}):
        values, info = run(DISCOVERY, discovery_body(**disagree, **extra))
        assert_not_evaluated_with_error(values, info, (disagree, extra))


@pytest.mark.parametrize("overrides", [
    {"status": "error"},
    {"status": "error", "reason": "asm_scan_in_progress"},
    {"status": "error", "reason": "upstream_unavailable"},
    {"status": "error", "reason": "<script>"},
    {"status": "success", "domainsScanned": "0"},
    {"status": "success", "templatesScanned": "0"},
    {"status": "success", "errors": [{"domain": "example.com", "error": "x"}]},
])
def test_discovery_a_scan_that_did_not_complete_is_none_even_when_stale_or_untimed(overrides):
    for extra in ({}, {"timestamp": stamp(200)}, {"timestamp": ""}):
        values, info = run(DISCOVERY, discovery_body(**overrides, **extra))
        assert values == {"isContinuousDiscoveryEnabled": None}, (overrides, extra, values)
        assert collection(info)["status"] == "error"


def test_discovery_a_fresh_complete_scan_still_passes():
    values, info = run(DISCOVERY, discovery_body(timestamp=stamp(1)))
    assert values["isContinuousDiscoveryEnabled"] is True
    assert collection(info)["status"] == "success"


# vulnerabilityScanFrequency: a timestamp that cannot place the scan in time measured nothing, so it is None with
# its error, never False. A stale one (readable, more than 7 days old) is still a graded False.
FREQUENCY = "vulnerabilityscanfrequency.py"
FREQUENCY_KEY = "vulnerabilityScanFrequency"


def frequency_body(timestamp="absent"):
    body = success_body()
    if timestamp == "absent":
        del body["timestamp"]
    else:
        body["timestamp"] = timestamp
    return body


@pytest.mark.parametrize("timestamp", ["absent", "", None, "   ", "yesterday", "not a date", "2026-13-45T00:00:00Z",
                                       1760000000, 1760000000.5, ["2026-10-12"], {"a": 1}])
def test_frequency_a_missing_or_unparseable_timestamp_is_none_with_its_error(timestamp):
    values, info = run(FREQUENCY, frequency_body(timestamp))
    assert values == {FREQUENCY_KEY: None}, (timestamp, values)
    assert collection(info)["status"] == "error"
    assert collection(info)["errors"]
    assert info["evaluation"]["failReasons"]


@pytest.mark.parametrize("hours_ahead", [2, 48, 24 * 30])
def test_frequency_a_future_timestamp_is_none_with_its_error(hours_ahead):
    values, info = run(FREQUENCY, frequency_body(stamp(-hours_ahead)))
    assert values == {FREQUENCY_KEY: None}, (hours_ahead, values)
    assert collection(info)["status"] == "error"
    assert collection(info)["errors"]
    assert info["evaluation"]["failReasons"]


def test_frequency_a_timestamp_a_few_minutes_ahead_is_clock_skew_and_reads_as_today():
    values, info = run(FREQUENCY, frequency_body(stamp(-0.5)))
    assert values[FREQUENCY_KEY] is True
    assert values["daysSinceLastScan"] == 0
    assert collection(info)["status"] == "success"


@pytest.mark.parametrize("hours,expected", [(1, True), (24 * 7, True), (24 * 8 + 1, False), (24 * 30, False)])
def test_frequency_a_readable_timestamp_in_the_past_is_still_a_graded_answer(hours, expected):
    values, info = run(FREQUENCY, frequency_body(stamp(hours)))
    assert values[FREQUENCY_KEY] is expected, (hours, values)
    assert collection(info)["status"] == "success"
    assert collection(info)["errors"] == []
