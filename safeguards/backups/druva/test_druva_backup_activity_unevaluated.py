"""Druva Backup Activity transforms: a read that measured nothing is Unevaluated, not a finding (2026-10-01).

isBackupTypesScheduled, backupSuccessRatePercentage and failedBackupJobsCount read the Druva
Backup Activity report (ewBackupActivity). The report holds only jobs that Druva's reporting store
has synced, about once a day, so a read whose window starts after the last sync returns zero jobs
even when every backup set is enabled and the last nightly run was all Successful. The backup-set
count is a different report, so zero jobs must come back as None with dataCollection.status
"error" (Token-Service reads that as Unevaluated), never False and never None-as-finding. The same
holds for a missing, error, unrecognised or partial read. A body that lists jobs still answers.

Each case runs twice: as plain Python, and in the Token-Service sandbox replica
(tools/restricted_sandbox.py) on the body Token-Service would hand the transform (the envelope
drilled to its row list), when RestrictedPython is installed.

All fixtures are synthetic: invented backup-set names, policies, job ids and timestamps.
"""
import copy
import importlib.util
import json
import pathlib

import pytest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]

KEYS = ["isBackupTypesScheduled", "backupSuccessRatePercentage", "failedBackupJobsCount"]

try:
    import RestrictedPython  # noqa: F401
    spec = importlib.util.spec_from_file_location("restricted_sandbox_druva", ROOT / "tools" / "restricted_sandbox.py")
    sandbox = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sandbox)
    HAVE_SANDBOX = True
except ImportError:
    sandbox = None
    HAVE_SANDBOX = False

MODES = ["python", pytest.param("sandbox", marks=pytest.mark.skipif(not HAVE_SANDBOX, reason="RestrictedPython not installed"))]


def load(key, mode):
    path = HERE / (key.lower() + ".py")
    if mode == "sandbox":
        return sandbox.load(path.read_text(), "<transformation>")["transform"]
    spec = importlib.util.spec_from_file_location("druva_" + key, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.transform


def ts_drill(body):
    """What Token-Service hands a legacy transform: codeexecutor.py walks these keys in order."""
    current = body
    for key in ("response", "result", "apiResponse", "Output", "data"):
        if isinstance(current, dict) and key in current:
            current = current[key]
    return current


def run(key, body, mode):
    out = load(key, mode)(copy.deepcopy(body))
    return out["transformedResponse"][key], out


def assert_unevaluated(key, body, mode):
    value, out = run(key, body, mode)
    assert value is None, (key, body, value)
    collection = out["additionalInfo"]["dataCollection"]
    assert collection["status"] == "error", (key, body, collection)
    assert collection["errors"], (key, body)
    assert out["additionalInfo"]["evaluation"]["failReasons"], (key, body)
    return out


def job(n, status="Successful", scheduled="2026-01-10T02:00:00Z", policy="Synthetic Nightly Policy"):
    return {"jobID": 700000 + n, "backupset": "synthetic-set-%02d" % n, "resourceName": "synthetic-vm-%02d" % n,
            "status": status, "scheduled": scheduled, "backupPolicy": policy,
            "startTime": "2026-01-10T02:00:00Z", "endTime": "2026-01-10T02:20:00Z",
            "lastUpdatedTime": "2026-01-10T02:20:00Z", "organization": "Synthetic Org"}


def envelope(rows, last_sync="2026-01-10T06:00:00Z", window_start="2026-01-09T12:00:00Z", next_token=""):
    return {"data": rows,
            "filters": {"pageSize": "500",
                        "filterBy": [{"columnName": "lastUpdatedTime", "operator": "GTE", "value": window_start}]},
            "lastSyncTimestamp": last_sync,
            "nextPageToken": next_token}


NO_EVIDENCE = {
    "null": None,
    "empty_dict": {},
    "empty_json_string": "{}",
    "malformed_json": "{not json",
    "bytes_null": b"null",
    "auth_401": {"statusCode": 401, "error": "Unauthorized"},
    "auth_403_string_code": {"status_code": "403", "message": "Forbidden"},
    "vendor_error": {"code": 400, "message": "Invalid filter value", "errorCode": "EW-SYNTHETIC"},
    "vendor_error_nested": {"error": {"code": "invalid_token", "message": "token expired"}},
    "platform_error": {"status": "Error", "message": "upstream call failed"},
    "unrelated": {"hello": "world"},
    "data_without_sync": {"data": [{"status": "Successful"}]},
    "data_not_a_list": {"data": {"status": "Successful"}, "lastSyncTimestamp": "2026-01-10T06:00:00Z"},
    "wrapped_error": {"response": {"result": {"statusCode": 500, "error": "Internal"}}},
    "non_job_rows": [{"hello": "world"}, {"foo": 1}],
    "non_dict_rows": [1, "two", None],
    "validation_failed": {"data": [{"status": "Successful"}],
                          "validation": {"status": "failed", "errors": ["schema mismatch"], "warnings": []}},
}

# Zero jobs: the case that turned 6 checks from pass to FINDING in prod.
EMPTY_READS = {
    "drilled_list": [],
    "drilled_list_json": "[]",
    "envelope_synced_before_window": envelope([], last_sync="2026-01-09T18:20:45Z", window_start="2026-01-10T20:51:45Z"),
    "envelope_synced_inside_window": envelope([], last_sync="2026-01-10T06:00:00Z", window_start="2026-01-09T12:00:00Z"),
    "envelope_wrapped": {"response": {"result": envelope([])}},
}


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("name", sorted(NO_EVIDENCE))
@pytest.mark.parametrize("key", KEYS)
def test_no_evidence_is_unevaluated(key, name, mode):
    assert_unevaluated(key, NO_EVIDENCE[name], mode)


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("name", sorted(EMPTY_READS))
@pytest.mark.parametrize("key", KEYS)
def test_zero_jobs_is_unevaluated_not_a_finding(key, name, mode):
    out = assert_unevaluated(key, EMPTY_READS[name], mode)
    assert "no jobs" in out["additionalInfo"]["dataCollection"]["errors"][0]


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("key", KEYS)
def test_zero_jobs_as_token_service_hands_it(key, mode):
    # prod: the envelope is drilled to its (empty) row list before the transform runs
    assert_unevaluated(key, ts_drill(envelope([])), mode)


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("key", KEYS)
def test_stale_sync_is_named(key, mode):
    body = EMPTY_READS["envelope_synced_before_window"]
    out = assert_unevaluated(key, body, mode)
    reason = out["additionalInfo"]["dataCollection"]["errors"][0]
    assert "empty by construction" in reason
    assert "2026-01-09T18:20:45Z" in reason


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("key", KEYS)
def test_sync_inside_window_does_not_claim_stale(key, mode):
    out = assert_unevaluated(key, EMPTY_READS["envelope_synced_inside_window"], mode)
    assert "empty by construction" not in out["additionalInfo"]["dataCollection"]["errors"][0]


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("key", KEYS)
def test_transformation_exception_is_unevaluated(key, mode):
    class Exploding(dict):
        def get(self, *a, **k):
            raise RuntimeError("synthetic failure")
    if mode == "sandbox":
        pytest.skip("a dict subclass is not a body Token-Service can hand the sandbox")
    out = assert_unevaluated(key, Exploding(data=[]), mode)
    assert out["additionalInfo"]["transformation"]["status"] == "error"


# ---- real measurements still answer ------------------------------------------------------------

ALL_OK = [job(i) for i in range(1, 32)]
MIXED = [job(1), job(2), job(3, status="Failed"), job(4, status="Successful with errors")]
UNSCHEDULED = [job(1, scheduled="NA", policy="NA"), job(2, scheduled="", policy="Synthetic Policy")]


def measured_bodies(rows):
    return {"drilled": ts_drill(envelope(rows)), "envelope": envelope(rows),
            "json_string": json.dumps(ts_drill(envelope(rows)))}


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("shape", ["drilled", "envelope", "json_string"])
def test_measured_reads_answer(shape, mode):
    ok = measured_bodies(ALL_OK)[shape]
    mixed = measured_bodies(MIXED)[shape]
    unscheduled = measured_bodies(UNSCHEDULED)[shape]

    assert run("isBackupTypesScheduled", ok, mode)[0] is True
    assert run("isBackupTypesScheduled", unscheduled, mode)[0] is False
    assert run("backupSuccessRatePercentage", ok, mode)[0] == 100.0
    assert run("backupSuccessRatePercentage", mixed, mode)[0] == 50.0
    assert run("failedBackupJobsCount", ok, mode)[0] == 0
    assert run("failedBackupJobsCount", mixed, mode)[0] == 2

    for key, body in (("isBackupTypesScheduled", unscheduled), ("failedBackupJobsCount", mixed),
                      ("backupSuccessRatePercentage", mixed), ("isBackupTypesScheduled", ok)):
        out = run(key, body, mode)[1]
        assert out["additionalInfo"]["dataCollection"]["status"] == "success", (key, out)


@pytest.mark.parametrize("mode", MODES)
def test_measured_false_is_a_finding_with_reasons(mode):
    value, out = run("isBackupTypesScheduled", UNSCHEDULED, mode)
    assert value is False
    assert out["additionalInfo"]["evaluation"]["failReasons"]
    assert out["additionalInfo"]["evaluation"]["recommendations"]


@pytest.mark.parametrize("mode", MODES)
def test_row_without_status_still_counts_as_failed(mode):
    # unchanged semantics: once the read is recognisably job rows, a row with no status is not Successful
    rows = [job(1), {"jobID": 1, "backupset": "synthetic-set-x"}]
    assert run("failedBackupJobsCount", rows, mode)[0] == 1
    assert run("backupSuccessRatePercentage", rows, mode)[0] == 50.0


# ---- partial reads ----------------------------------------------------------------------------

@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("flag", ["next_token", "paginationTruncated", "truncated"])
def test_partial_read(flag, mode):
    def partial(rows):
        body = envelope(rows, next_token="synthetic-cursor" if flag == "next_token" else "")
        if flag != "next_token":
            body[flag] = True
        return body

    # counts over an unread remainder are not measurements
    assert_unevaluated("backupSuccessRatePercentage", partial(MIXED), mode)
    assert_unevaluated("failedBackupJobsCount", partial(MIXED), mode)
    assert_unevaluated("failedBackupJobsCount", partial(ALL_OK), mode)
    # a scheduled job on the pages read is still evidence; its absence there is not
    assert run("isBackupTypesScheduled", partial(ALL_OK), mode)[0] is True
    assert_unevaluated("isBackupTypesScheduled", partial(UNSCHEDULED), mode)


# ---- the old behaviour must not come back -------------------------------------------------------

@pytest.mark.parametrize("key", KEYS)
def test_zero_jobs_never_false(key):
    # the 1 Oct defect: [] scored False (isBackupTypesScheduled) or a bare None with
    # dataCollection "success", which Token-Service compared and rendered as a FINDING
    for body in list(EMPTY_READS.values()) + list(NO_EVIDENCE.values()):
        value, out = run(key, body, "python")
        assert value is not False, (key, body)
        assert out["additionalInfo"]["dataCollection"]["status"] == "error", (key, body)


def test_only_counts_leave_the_transform():
    # resource names and backup-set names from the rows are not copied into the output
    for key in KEYS:
        out = run(key, ALL_OK, "python")[1]
        dumped = json.dumps(out)
        assert "synthetic-vm-" not in dumped and "synthetic-set-" not in dumped, key
