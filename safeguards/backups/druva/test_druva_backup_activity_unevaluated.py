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
from datetime import datetime, timedelta

import pytest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]

KEYS = ["isBackupTypesScheduled", "backupSuccessRatePercentage", "failedBackupJobsCount"]

try:
    import RestrictedPython  # noqa: F401
    spec = importlib.util.spec_from_file_location("restricted_sandbox_druva", ROOT / "tools" / "restricted_sandbox.py")
    sandbox = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sandbox)
    load_code = sandbox.load
except ImportError:
    # same fallback as the Veeam tests: without RestrictedPython the "sandbox" leg runs as plain exec
    # (CI installs requirements-test.txt, which carries RestrictedPython, so CI runs the real sandbox)
    def load_code(code, filename):
        ns = {"__name__": "druva_sandbox"}
        exec(compile(code, filename, "exec"), ns)
        return ns

MODES = ["python", "sandbox"]


def load(key, mode):
    path = HERE / (key.lower() + ".py")
    if mode == "sandbox":
        return load_code(path.read_text(), "<transformation>")["transform"]
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
    return {"jobID": 700000 + n, "backupSet": "synthetic-set-%02d" % n, "deviceName": "synthetic-vm-%02d" % n,
            "status": status, "scheduled": scheduled, "backupPolicy": policy,
            "started": "2026-01-10T02:00:00.000Z", "ended": "2026-01-10T02:20:00.000Z",
            "lastUpdatedTime": "2026-01-10T02:20:00.000Z", "organization": "Synthetic Org"}


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


@pytest.mark.parametrize("key", KEYS)
def test_transformation_exception_is_unevaluated(key):
    # plain Python only: a dict subclass is not a body Token-Service can hand the sandbox
    class Exploding(dict):
        def get(self, *a, **k):
            raise RuntimeError("synthetic failure")
    out = assert_unevaluated(key, Exploding(data=[]), "python")
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
    assert run("backupSuccessRatePercentage", mixed, mode)[0] == 75.0  # "Successful with errors" passes
    assert run("failedBackupJobsCount", ok, mode)[0] == 0
    assert run("failedBackupJobsCount", mixed, mode)[0] == 1

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
def test_row_without_status_is_ignored_not_scored(mode):
    # once the read is recognisably job rows, a row with no status is not a job: it is counted as read, never scored
    rows = [job(1), {"jobID": 1, "backupSet": "synthetic-set-x"}]
    assert both(rows, mode) == (100.0, 0)
    counts = run("failedBackupJobsCount", rows, mode)[1]["transformedResponse"]
    assert (counts["backupJobsReported"], counts["backupRowsIgnored"], counts["backupSetsEvaluated"]) == (2, 1, 1)


# ---- latest finished job per backup set ----------------------------------------------------------

MISSING = object()  # an `at()` field set to this is left out of the row


def at(n, hour, status, **extra):
    """Job n of one backup set (same set descriptors), started at the given hour."""
    row = job(1, status=status)
    row.update({"jobID": 800000 + n, "started": "2026-01-10T%02d:00:00.000Z" % hour, "scheduled": "NA"})
    row.update(extra)
    return {k: v for k, v in row.items() if v is not MISSING}


NOW = datetime(2026, 1, 11, 12, 0, 0)  # the report's data time in the retry-cutoff tests (never the wall clock)
SYNC = NOW.strftime("%Y-%m-%dT%H:%M:%SZ")


def ago(hours):
    """A started stamp this many hours before the fixed data time NOW."""
    return (NOW - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def both(rows, mode, sync=None):
    body = envelope(rows, last_sync=sync) if sync else rows
    return (run("backupSuccessRatePercentage", body, mode)[0], run("failedBackupJobsCount", body, mode)[0])


@pytest.mark.parametrize("mode", MODES)
def test_later_success_supersedes_earlier_failure(mode):
    rows = [at(2, 9, "Successful"), at(1, 3, "Failed")]  # newest listed first on purpose
    assert both(rows, mode) == (100.0, 0)
    out = run("failedBackupJobsCount", rows, mode)[1]
    assert out["transformedResponse"]["backupJobsSuperseded"] == 1
    assert out["transformedResponse"]["backupSetsEvaluated"] == 1


@pytest.mark.parametrize("mode", MODES)
def test_status_less_row_cannot_supersede_a_real_job(mode):
    # same set descriptors, newer than the successful job, but no status: it must not turn the set into a failure
    rows = [at(1, 3, "Successful"), {k: v for k, v in at(2, 9, "Successful").items() if k != "status"}]
    assert both(rows, mode) == (100.0, 0)


@pytest.mark.parametrize("mode", MODES)
def test_later_failure_supersedes_earlier_success(mode):
    assert both([at(1, 3, "Successful"), at(2, 9, "Failed")], mode) == (0.0, 1)


@pytest.mark.parametrize("mode", MODES)
def test_jobid_breaks_a_time_tie_within_a_set(mode):
    assert both([at(2, 3, "Failed"), at(1, 3, "Successful")], mode) == (0.0, 1)


@pytest.mark.parametrize("mode", MODES)
def test_in_flight_jobs_are_in_neither_side(mode):
    rows = [job(1), job(2, status="Failed"), job(3, status="Queued"), job(4, status="RUNNING")]
    assert both(rows, mode) == (50.0, 1)
    out = run("backupSuccessRatePercentage", rows, mode)[1]
    assert out["transformedResponse"]["backupJobsInFlight"] == 2
    assert out["transformedResponse"]["backupSetsEvaluated"] == 2
    # an in-flight retry does not hide the finished failure before it
    assert both([at(1, 3, "Failed"), at(2, 9, "Running")], mode) == (0.0, 1)


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("key", ["backupSuccessRatePercentage", "failedBackupJobsCount"])
def test_all_in_flight_is_unevaluated(key, mode):
    out = assert_unevaluated(key, [job(1, status="Queued"), job(2, status="Running")], mode)
    assert "in flight" in out["additionalInfo"]["dataCollection"]["errors"][0]


@pytest.mark.parametrize("mode", MODES)
def test_same_backupset_different_device_is_not_merged(mode):
    rows = [at(1, 3, "Failed", deviceName="synthetic-vm-a"), at(2, 9, "Successful", deviceName="synthetic-vm-b")]
    assert both(rows, mode) == (50.0, 1)


@pytest.mark.parametrize("mode", MODES)
def test_host_less_rows_keep_hosts_apart_by_configuration_mode(mode):
    # real rows carry deviceName and vm as "NA"; for VMs the host lives in configurationMode
    rows = [at(1, 3, "Failed", deviceName="NA", vm="NA", configurationMode="synthetic-vc-a:DR1"),
            at(2, 9, "Successful", deviceName="NA", vm="NA", configurationMode="synthetic-vc-b:DR1")]
    assert both(rows, mode) == (50.0, 1)


@pytest.mark.parametrize("mode", MODES)
def test_completed_with_errors_fails_and_successful_with_errors_passes(mode):
    assert both([job(1, status="Completed with errors"), job(2, status="Successful with errors")], mode) == (50.0, 1)
    out = run("failedBackupJobsCount", [job(1, status="Completed with errors")], mode)[1]
    assert out["transformedResponse"]["nonSuccessfulStatuses"] == {"Completed with errors": 1}


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("backup_set", ["NA", "", None])
def test_rows_without_a_backupset_are_not_merged(backup_set, mode):
    rows = [at(1, 3, "Failed", backupSet=backup_set), at(2, 9, "Successful", backupSet=backup_set)]
    assert both(rows, mode) == (50.0, 1)


@pytest.mark.parametrize("mode", MODES)
def test_reason_names_basis_and_window_never_24_hours(mode):
    rows = [at(1, 3, "Failed"), at(2, 9, "Successful"), job(5, status="Queued")]
    for key in ("backupSuccessRatePercentage", "failedBackupJobsCount"):
        out = run(key, envelope(rows), mode)[1]
        reason = (out["additionalInfo"]["evaluation"]["passReasons"] + out["additionalInfo"]["evaluation"]["failReasons"])[0]
        assert "backup sets' latest finished job" in reason and "1 in-flight jobs excluded" in reason
        assert "1 earlier jobs superseded" in reason and "since 2026-01-09T12:00:00Z" in reason
        assert "24 hours" not in reason


def both_orders(rows, mode, sync=None):
    """Result must not depend on input order."""
    forward, backward = both(rows, mode, sync), both(rows[::-1], mode, sync)
    assert forward == backward, (forward, backward)
    return forward


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("winner", ["Failed", "Successful"])
def test_jobid_breaks_a_time_tie_in_either_order(winner, mode):
    # the higher jobID wins whatever its status and wherever it is listed
    loser = "Successful" if winner == "Failed" else "Failed"
    result = both_orders([at(1, 3, loser), at(2, 3, winner)], mode)
    assert result == ((0.0, 1) if winner == "Failed" else (100.0, 0))


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("later", ["Failed", "Successful"])
def test_time_beats_jobid(later, mode):
    # the later start has the LOWER jobID: time is the primary order
    earlier = "Successful" if later == "Failed" else "Failed"
    result = both_orders([at(1, 9, later), at(2, 3, earlier)], mode)
    assert result == ((0.0, 1) if later == "Failed" else (100.0, 0))


@pytest.mark.parametrize("mode", MODES)
def test_full_tie_is_deterministic_and_fails_safe(mode):
    # same time, no usable jobID: a failing job beats a passing one in either order
    failed, ok = at(1, 3, "Failed", jobID=MISSING), at(2, 3, "Successful", jobID=MISSING)
    assert both_orders([failed, ok], mode) == (0.0, 1)
    same_id = ({"jobID": 5}, {"jobID": 5})
    assert both_orders([at(1, 3, "Failed", **same_id[0]), at(2, 3, "Successful", **same_id[1])], mode) == (0.0, 1)


@pytest.mark.parametrize("mode", MODES)
def test_scheduled_orders_rows_without_a_start(mode):
    # newest by `scheduled` is the Failed one although the Successful one has the higher jobID
    rows = [at(1, 3, "Failed", started="NA", scheduled="2026-01-10T09:00:00Z"),
            at(2, 3, "Successful", started="NA", scheduled="2026-01-10T03:00:00Z")]
    assert both_orders(rows, mode) == (0.0, 1)


@pytest.mark.parametrize("mode", MODES)
def test_last_updated_time_orders_rows_with_no_start_or_schedule(mode):
    rows = [at(1, 3, "Failed", started="NA", lastUpdatedTime="2026-01-10T09:00:00.000Z"),
            at(2, 3, "Successful", started="NA", lastUpdatedTime="2026-01-10T03:00:00.000Z")]
    assert both_orders(rows, mode) == (0.0, 1)


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("untimed_status", ["Failed", "Successful"])
def test_row_with_no_parseable_time_sorts_oldest(untimed_status, mode):
    # the untimed row has the higher jobID and still loses to any timed row
    timed = "Successful" if untimed_status == "Failed" else "Failed"
    rows = [at(1, 3, timed), at(2, 3, untimed_status, started="NA", lastUpdatedTime="NA")]
    assert both_orders(rows, mode) == ((0.0, 1) if timed == "Failed" else (100.0, 0))


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("field", ["organization", "administrativeGroup", "vm", "resourceType", "configurationMode"])
def test_each_identity_field_keeps_sets_apart(field, mode):
    rows = [at(1, 3, "Failed", **{field: "synthetic-a"}), at(2, 9, "Successful", **{field: "synthetic-b"})]
    assert both(rows, mode) == (50.0, 1)


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("status", ["Waiting", "In Progress", "WAITING", "in progress"])
def test_waiting_and_in_progress_are_in_flight(status, mode):
    rows = [job(1), job(2, status="Failed"), job(3, status=status)]
    assert both(rows, mode) == (50.0, 1)
    assert run("failedBackupJobsCount", rows, mode)[1]["transformedResponse"]["backupJobsInFlight"] == 1


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("job_id", [MISSING, None, "NA", "abc", "\u00b2", 12345678901234567890, "12345678901234567890"])
def test_unparseable_jobid_still_evaluates(job_id, mode):
    # the later Successful wins on time; a bad jobID on either row must not turn the read Unevaluated
    for rows in ([at(1, 3, "Failed", jobID=job_id), at(2, 9, "Successful")],
                 [at(1, 3, "Failed"), at(2, 9, "Successful", jobID=job_id)]):
        assert both_orders(rows, mode) == (100.0, 0)
        out = run("failedBackupJobsCount", rows, mode)[1]
        assert out["additionalInfo"]["dataCollection"]["status"] == "success"


@pytest.mark.parametrize("mode", MODES)
def test_every_time_field_unparseable_does_not_raise(mode):
    blank = {"started": "NA", "scheduled": "NA", "lastUpdatedTime": "NA", "jobID": MISSING}
    assert both([at(1, 3, "Successful", **blank)], mode) == (100.0, 0)
    assert both_orders([at(1, 3, "Failed", **blank), at(2, 3, "Successful", **blank)], mode) == (0.0, 1)


@pytest.mark.parametrize("mode", MODES)
def test_mixed_read_counts_add_up_and_leak_nothing(mode):
    rows = [job(1), job(2, status="Failed"), job(3, status="Queued"), job(4, status="Waiting"),
            job(5), at(1, 9, "Failed")]  # at(1, ...) is a later run of job(1)'s set, so it supersedes job(1)
    for key in ("backupSuccessRatePercentage", "failedBackupJobsCount"):
        value, out = run(key, rows, mode)
        counts = out["transformedResponse"]
        assert counts["backupJobsReported"] == 6
        assert counts["backupJobsReported"] == (counts["backupJobsInFlight"] + counts["backupJobsSuperseded"]
                                                + counts["backupSetsRetrying"] + counts["backupSetsEvaluated"]
                                                + counts["backupRowsIgnored"])
        assert counts["backupRowsIgnored"] == 0
        assert (counts["backupJobsInFlight"], counts["backupJobsSuperseded"], counts["backupSetsEvaluated"]) == (2, 1, 3)
        assert value == (33.33 if key == "backupSuccessRatePercentage" else 2)
        assert "synthetic-" not in json.dumps(out)


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


# ---- review round: unfinished status variants, one time source per set, UTC offsets -------------

@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("status", ["Scheduled", "Waiting", "Pending", "Starting", "In Progress", "Queued (2)", "Running - 40%"])
def test_unfinished_status_variants_are_excluded_not_failed(status, mode):
    # a newer unfinished job must neither fail the set nor hide its last finished result
    rows = [at(1, 3, "Successful"), at(2, 9, status)]
    assert both_orders(rows, mode) == (100.0, 0)
    out = run("failedBackupJobsCount", rows, mode)[1]
    assert out["transformedResponse"]["backupJobsInFlight"] == 1


@pytest.mark.parametrize("mode", MODES)
def test_set_ranks_on_one_time_field_when_rows_carry_different_ones(mode):
    # by `started` the Failed row would look older (03:00 vs a 09:00 schedule), but only `scheduled` is on both rows,
    # and by schedule the Failed run is the newer one
    rows = [at(1, 3, "Successful", scheduled="2026-01-10T01:00:00Z"),
            at(2, 3, "Failed", started="NA", scheduled="2026-01-10T02:00:00Z")]
    assert both_orders(rows, mode) == (0.0, 1)


@pytest.mark.parametrize("mode", MODES)
def test_utc_offsets_are_applied_before_comparing(mode):
    # 08:00+07:00 is 01:00 UTC, so the Successful job at 03:00Z is the newer one
    rows = [at(1, 3, "Successful", jobID=800001),
            at(2, 8, "Failed", jobID=800002, started="2026-01-10T08:00:00.000+07:00")]
    assert both_orders(rows, mode) == (100.0, 0)


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("status", ["Paused", "Resuming"])
def test_paused_states_score_as_not_passing(status, mode):
    # these follow a stopped attempt: an older Successful job must not decide the set (fail closed)
    assert both_orders([at(1, 3, "Successful"), at(2, 9, status)], mode) == (0.0, 1)


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("earlier", ["Successful", "Failed"])
def test_waiting_for_retry_is_neither_pass_nor_fail(earlier, mode):
    # a set whose latest job is Waiting for retry leaves both sides; the older job does not decide it either way
    rows = [at(1, 3, earlier, started=ago(5)), at(2, 9, "Waiting for retry", started=ago(2)), job(5), job(6, status="Failed")]
    assert both_orders(rows, mode) == (50.0, 1)
    counts = run("failedBackupJobsCount", rows, mode)[1]["transformedResponse"]
    assert (counts["backupSetsRetrying"], counts["backupSetsEvaluated"], counts["backupJobsSuperseded"]) == (1, 2, 1)
    reason = run("backupSuccessRatePercentage", rows, mode)[1]["additionalInfo"]["evaluation"]["passReasons"][0]
    assert "1 sets waiting for retry excluded" in reason


def stale_mix(first, retry_started, **retry_extra):
    # one retrying set, one passing set, one failing set
    return [at(1, 3, "Failed", started=first), at(2, 9, "Waiting for retry", started=retry_started, **retry_extra), job(5), job(6, status="Failed")]


@pytest.mark.parametrize("mode", MODES)
def test_retrying_set_older_than_the_cutoff_counts_as_failed(mode):
    rows = stale_mix(ago(30), ago(26))
    assert both_orders(rows, mode, SYNC) == (round(100.0 / 3, 2), 2)
    counts = run("failedBackupJobsCount", envelope(rows, last_sync=SYNC), mode)[1]["transformedResponse"]
    assert (counts["backupSetsRetrying"], counts["backupSetsRetryingStale"], counts["backupSetsEvaluated"]) == (1, 1, 3)
    assert counts["nonSuccessfulStatuses"] == {"Waiting for retry": 1, "Failed": 1}
    ev = run("failedBackupJobsCount", envelope(rows, last_sync=SYNC), mode)[1]["additionalInfo"]["evaluation"]
    reason = (ev["passReasons"] + ev["failReasons"])[0]
    assert "0 sets waiting for retry excluded" in reason and "1 sets waiting for retry for over 24 hours counted as failed" in reason


@pytest.mark.parametrize("mode", MODES)
def test_retrying_set_ages_from_its_first_failed_attempt_not_the_latest_retry(mode):
    # the newest retry row is young, but the set has been failing for 30h
    assert both_orders(stale_mix(ago(30), ago(1)), mode, SYNC) == (round(100.0 / 3, 2), 2)


@pytest.mark.parametrize("mode", MODES)
def test_retrying_set_younger_than_the_cutoff_is_neither(mode):
    assert both_orders(stale_mix(ago(20), ago(1)), mode, SYNC) == (50.0, 1)


@pytest.mark.parametrize("mode", MODES)
def test_an_older_success_does_not_age_a_fresh_retry(mode):
    rows = [at(1, 3, "Successful", started=ago(60)), at(2, 9, "Waiting for retry", started=ago(1)), job(5)]
    assert both_orders(rows, mode) == (100.0, 0)


@pytest.mark.parametrize("mode", MODES)
def test_retrying_set_with_no_usable_timestamp_stays_uncounted(mode):
    rows = [at(1, 9, "Waiting for retry", started="NA", lastUpdatedTime="NA"), job(5), job(6, status="Failed")]
    assert both_orders(rows, mode) == (50.0, 1)
    out = run("backupSuccessRatePercentage", rows, mode)[1]
    ev = out["additionalInfo"]["evaluation"]
    assert "1 with no usable timestamp" in (ev["passReasons"] + ev["failReasons"])[0]


@pytest.mark.parametrize("mode", MODES)
def test_age_is_measured_from_the_report_sync_time_not_the_clock(mode):
    rows = stale_mix(ago(20), ago(1))
    assert both_orders(rows, mode, SYNC) == (50.0, 1)  # 20h old at the sync: still waiting
    later = (NOW + timedelta(hours=6)).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert both_orders(rows, mode, later) == (round(100.0 / 3, 2), 2)  # the same body, 26h old at a later sync
    # a replay months later gives the same answer: the wall clock is not read
    assert both_orders(rows, mode, SYNC) == (50.0, 1)


@pytest.mark.parametrize("mode", MODES)
def test_without_a_sync_time_age_runs_to_the_newest_timestamp_in_the_data(mode):
    # bare row list: the newest started stamp (the fresh Successful job) is the report's "now"
    fresh = dict(job(7), started=ago(0), lastUpdatedTime=ago(0))
    assert both_orders(stale_mix(ago(30), ago(26)) + [fresh], mode) == (50.0, 2)
    assert both_orders(stale_mix(ago(20), ago(1)) + [fresh], mode) == (66.67, 1)


@pytest.mark.parametrize("mode", MODES)
def test_rows_with_no_shared_time_field_leave_the_retrying_set_uncounted(mode):
    # the Failed row only has started, the retrying row only lastUpdatedTime: no common clock, so no age
    rows = [at(1, 3, "Failed", started=ago(40), lastUpdatedTime="NA"),
            at(2, 9, "Waiting for retry", started=MISSING, lastUpdatedTime=ago(30)), job(5)]
    assert both_orders(rows, mode, SYNC) == (100.0, 0)


@pytest.mark.parametrize("mode", MODES)
def test_mixed_time_fields_are_compared_on_the_shared_one(mode):
    # started would say the success is newer than the retry's lastUpdatedTime; on the shared lastUpdatedTime the retry is 30h old
    rows = [at(1, 3, "Successful", started=ago(2), lastUpdatedTime=ago(40)),
            at(2, 9, "Waiting for retry", started=MISSING, lastUpdatedTime=ago(30)), job(5)]
    assert both_orders(rows, mode, SYNC) == (50.0, 1)


@pytest.mark.parametrize("mode", MODES)
def test_only_stale_retrying_sets_are_evaluated_as_failed(mode):
    assert both_orders([at(1, 3, "Waiting for retry", started=ago(40))], mode, SYNC) == (0.0, 1)


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("key", ["backupSuccessRatePercentage", "failedBackupJobsCount"])
def test_only_retrying_sets_is_unevaluated(key, mode):
    out = assert_unevaluated(key, [at(1, 3, "Failed", started=ago(5)), at(2, 9, "Waiting for retry", started=ago(2)), job(5, status="Queued")], mode)
    assert "waiting for retry" in out["additionalInfo"]["dataCollection"]["errors"][0]


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("stamp", ["0001-01-01T00:30:00+01:00", "9999-12-31T23:59:59-01:00"])
def test_offset_overflow_makes_only_that_row_untimed(stamp, mode):
    # an out-of-range offset must not make the whole read Not evaluated; the row just ranks as untimed,
    # so here the timed Failed job decides the set (the fixture does not rely on untimed-ranks-oldest to pass)
    rows = [at(1, 3, "Failed"), at(2, 9, "Successful", started=stamp, lastUpdatedTime="NA")]
    assert both_orders(rows, mode) == (0.0, 1)
    out = run("failedBackupJobsCount", rows, mode)[1]
    assert out["additionalInfo"]["dataCollection"]["status"] != "error"
