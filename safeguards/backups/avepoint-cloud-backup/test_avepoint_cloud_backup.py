"""AvePoint Cloud Backup for Microsoft 365: every transform, synthetic bodies only.

Fixture shapes follow the AvePoint Graph API documentation samples (no customer data; ids are zeros,
owners are @x.test):
  backup frequency  https://learn.avepoint.com/docs/services-and-features/m365/backup-frequency.html
  list jobs         https://learn.avepoint.com/docs/services-and-features/m365/jobs/list-jobs.html
  serviceType codes https://learn.avepoint.com/docs/services-and-features/m365/overview.html

Fail closed: a missing, error, vendorErrorAsResponse, partial or unrecognised body reads None, never True
and never False. Every case runs twice: plain Python and the production RestrictedPython sandbox.
"""
import importlib.util
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE.parents[2] / "tools"))

KEYS = ["isBackupEnabled", "isBackupTypesScheduled", "isBackupTested"]
FILES = {"isBackupEnabled": "isbackupenabled", "isBackupTypesScheduled": "isbackuptypesscheduled",
         "isBackupTested": "isbackuptested"}
FREQUENCY_KEYS = ["isBackupEnabled", "isBackupTypesScheduled"]


def load_plain(key):
    spec = importlib.util.spec_from_file_location("avepoint_" + FILES[key], HERE / (FILES[key] + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def load_sandbox(key):
    from restricted_sandbox import load as sandbox_load
    ns = sandbox_load((HERE / (FILES[key] + ".py")).read_text(), FILES[key] + ".py")
    return ns["transform"]


RUNNERS = {}
for _k in KEYS:
    RUNNERS[(_k, "plain")] = load_plain(_k)
try:
    import RestrictedPython  # noqa: F401
    for _k in KEYS:
        RUNNERS[(_k, "sandbox")] = load_sandbox(_k)
    MODES = ["plain", "sandbox"]
except ImportError:  # the CI sandbox job installs it; locally it may be absent
    MODES = ["plain"]


def run(key, mode, payload):
    return RUNNERS[(key, mode)](payload)


def value(key, mode, payload):
    return run(key, mode, payload)["transformedResponse"][key]


def envelope(data, **extra):
    body = {"statusCode": 200, "message": "", "data": data, "requestId": "0HN000000000:00000001",
            "timestamp": "2026-02-27T03:54:22.0000000Z", "traceId": "00-00000000000000000000000000000000-0000000000000000-00"}
    body.update(extra)
    return body


def freq(service, frequency, times=None):
    if times is None:
        times = ["2026-02-27T03:54:22Z"] * frequency
    return {"serviceType": service, "frequency": frequency, "backupStartTime": times}


def iso(days_ago):
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def job(n, state, days_ago, successful=3, field="successfulCount"):
    return {"id": "0000000000000000000000" + str(n), "state": state, "startTime": iso(days_ago),
            "finishTime": iso(days_ago), "duration": "0.011",
            "backupDetails": {"totalCount": successful, "failedCount": 0, field: successful, "skippedCount": 0},
            "jobErrors": []}


def jobs_body(items, total=None, next_link=""):
    return envelope(items, metadata={"totalCount": len(items) if total is None else total, "nextLink": next_link})


NO_EVIDENCE = [None, {}, "{}", "", b"", "not json", [], [{"x": 1}], {"hello": "world"},
               {"foo": {"bar": [1, 2, 3]}}, {"data": []}, {"statusCode": 200},
               {"statusCode": 200, "data": "not-a-list"},
               {"statusCode": 401, "message": "Unauthorized", "data": None},
               {"statusCode": 403, "message": "Forbidden", "data": []},
               {"statusCode": 500, "message": "Internal Server Error", "data": []},
               {"statusCode": 200, "data": [], "errors": [{"code": "x", "message": "y"}]},
               {"error": True, "errorType": "auth", "statusCode": 401},
               {"error": True, "errorType": "pagination_incomplete", "statusCode": 502},
               {"vendorErrorAsResponse": {"status": 403, "bodyContains": "x", "body": "{}"}},
               {"apiResponse": {"error": True, "statusCode": 500}}]


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("key", KEYS)
@pytest.mark.parametrize("body", NO_EVIDENCE, ids=lambda b: str(b)[:40])
def test_no_evidence_reads_none(key, mode, body):
    out = run(key, mode, body)
    assert out["transformedResponse"][key] is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("key", KEYS)
def test_permission_error_names_the_permission(key, mode):
    out = run(key, mode, {"vendorErrorAsResponse": {"status": 403, "bodyContains": "x", "body": "{}"}})
    assert out["transformedResponse"][key] is None
    assert out["additionalInfo"]["dataCollection"]["errorCode"] == "permission_not_granted"
    want = "microsoft365backup.jobInfo.read.all" if key == "isBackupTested" else "microsoft365backup.settings.read.all"
    assert out["additionalInfo"]["dataCollection"]["requiredPermission"] == want


# backup frequency -----------------------------------------------------------------------------------

DOC_SAMPLE = envelope([freq(0, 4, ["2026-02-27T03:54:22Z", "2026-02-27T09:54:22Z", "2026-02-27T15:54:22Z",
                                   "2026-02-27T21:54:22Z"]), freq(1, 1), freq(2, 1)])


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("key", FREQUENCY_KEYS)
def test_documented_sample_passes(key, mode):
    assert value(key, mode, DOC_SAMPLE) is True
    assert value(key, mode, json.dumps(DOC_SAMPLE)) is True
    assert value(key, mode, {"apiResponse": DOC_SAMPLE}) is True
    assert value(key, mode, {"validation": {"status": "valid"}, "data": DOC_SAMPLE}) is True
    assert value(key, mode, json.dumps(DOC_SAMPLE).encode("utf-8")) is True


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("key", FREQUENCY_KEYS)
def test_no_active_service_is_real_false(key, mode):
    out = run(key, mode, envelope([]))
    assert out["transformedResponse"][key] is False
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("key", FREQUENCY_KEYS)
def test_all_zero_frequency_is_real_false(key, mode):
    assert value(key, mode, envelope([freq(0, 0, []), freq(1, 0, [])])) is False


@pytest.mark.parametrize("mode", MODES)
def test_one_unscheduled_service_fails_scheduled_not_enabled(mode):
    body = envelope([freq(0, 4), freq(6, 0, [])])
    assert value("isBackupEnabled", mode, body) is True
    out = run("isBackupTypesScheduled", mode, body)
    assert out["transformedResponse"]["isBackupTypesScheduled"] is False
    assert "Teams: frequency 0" in out["transformedResponse"]["servicesNotScheduled"]


@pytest.mark.parametrize("mode", MODES)
def test_frequency_without_start_time_is_not_scheduled(mode):
    assert value("isBackupTypesScheduled", mode, envelope([freq(0, 1), freq(2, 1, [])])) is False


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("bad", [{"serviceType": 0}, {"serviceType": 0, "frequency": "4", "backupStartTime": []},
                                 {"serviceType": True, "frequency": 1, "backupStartTime": ["x"]},
                                 {"serviceType": 0, "frequency": 1, "backupStartTime": "2026-02-27T03:54:22Z"},
                                 {"serviceType": 0, "frequency": -1, "backupStartTime": []}, "entry"])
def test_unreadable_entry_is_none_for_scheduled(mode, bad):
    assert value("isBackupTypesScheduled", mode, envelope([freq(0, 4), bad])) is None


@pytest.mark.parametrize("mode", MODES)
def test_unreadable_entry_alone_is_none_for_enabled(mode):
    assert value("isBackupEnabled", mode, envelope([{"serviceType": 0}])) is None
    assert value("isBackupEnabled", mode, envelope([{"serviceType": 0}, freq(1, 0, [])])) is None
    assert value("isBackupEnabled", mode, envelope([{"serviceType": 0}, freq(1, 2)])) is True


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("key", FREQUENCY_KEYS)
def test_truncated_frequency_read_is_none(key, mode):
    body = dict(DOC_SAMPLE)
    body["paginationTruncated"] = True
    assert value(key, mode, body) is None


@pytest.mark.parametrize("mode", MODES)
def test_unknown_service_code_is_named(mode):
    out = run("isBackupEnabled", mode, envelope([freq(99, 1)]))
    assert out["transformedResponse"]["isBackupEnabled"] is True
    assert "serviceType 99" in out["additionalInfo"]["evaluation"]["passReasons"][0]


# restore jobs -----------------------------------------------------------------------------------------

@pytest.mark.parametrize("mode", MODES)
def test_recent_finished_restore_passes(mode):
    body = jobs_body([job(1, "Failed", 3), job(2, "Finished", 40)])
    out = run("isBackupTested", mode, body)
    assert out["transformedResponse"]["isBackupTested"] is True
    assert out["transformedResponse"]["qualifyingRestoreCount"] == 1
    assert value("isBackupTested", mode, json.dumps(body)) is True
    assert value("isBackupTested", mode, {"apiResponse": body}) is True


@pytest.mark.parametrize("mode", MODES)
def test_table_field_name_is_read_too(mode):
    assert value("isBackupTested", mode, jobs_body([job(1, "Finished", 5, 2, "successfulNumber")])) is True
    assert value("isBackupTested", mode, jobs_body([job(1, "Finished", 5, 0, "successfulNumber")])) is False


@pytest.mark.parametrize("mode", MODES)
def test_no_restore_is_real_false(mode):
    out = run("isBackupTested", mode, jobs_body([]))
    assert out["transformedResponse"]["isBackupTested"] is False
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("state", ["Failed", "Finished with Exception", "Partially Finished", "In Progress", ""])
def test_unsuccessful_restores_are_real_false(mode, state):
    assert value("isBackupTested", mode, jobs_body([job(1, state, 10), job(2, state, 20)])) is False


@pytest.mark.parametrize("mode", MODES)
def test_old_or_empty_restore_is_false(mode):
    assert value("isBackupTested", mode, jobs_body([job(1, "Finished", 400)])) is False
    assert value("isBackupTested", mode, jobs_body([job(1, "Finished", 10, 0)])) is False
    assert value("isBackupTested", mode, jobs_body([job(1, "Finished", -30)])) is False


@pytest.mark.parametrize("mode", MODES)
def test_unreadable_finish_time_is_none_unless_another_qualifies(mode):
    bad = job(1, "Finished", 10)
    bad["finishTime"] = "02/12/2024 07:53"
    assert value("isBackupTested", mode, jobs_body([bad])) is None
    assert value("isBackupTested", mode, jobs_body([bad, job(2, "Finished", 10)])) is True


@pytest.mark.parametrize("mode", MODES)
def test_partial_job_list_is_none(mode):
    failed = [job(1, "Failed", 10)]
    assert value("isBackupTested", mode, jobs_body(failed, next_link="https://graph-us.x.test/backup/m365/cloudbackupjobs?pageIndex=2")) is None
    assert value("isBackupTested", mode, jobs_body(failed, total=120)) is None
    truncated = jobs_body(failed)
    truncated["metadata"]["truncated"] = True
    assert value("isBackupTested", mode, truncated) is None
    marked = jobs_body(failed)
    marked["paginationTruncated"] = True
    assert value("isBackupTested", mode, marked) is None
    no_meta = envelope(failed)
    assert value("isBackupTested", mode, no_meta) is None


@pytest.mark.parametrize("mode", MODES)
def test_merged_pages_after_integration_service_paging(mode):
    # Integration-Service link paging clears metadata.nextLink and keeps page 1 totalCount.
    items = [job(n, "Failed", 10 + n) for n in range(1, 60)] + [job(99, "Finished", 9)]
    body = envelope(items, metadata={"totalCount": len(items), "nextLink": None})
    assert value("isBackupTested", mode, body) is True


@pytest.mark.parametrize("key", KEYS)
def test_sandbox_and_plain_agree_on_empty(key):
    for mode in MODES:
        assert value(key, mode, {}) is None
