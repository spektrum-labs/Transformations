"""Keepit checks built for the Atlas (Permasteelisa) gap: job history, retention, schedule and
multi-geo, on bodies shaped as Integration-Service hands them over (Keepit XML parsed by
xmltodict: one element is a dict, several a list, empty is None, booleans are strings).

The listDevices shape copies a real Keepit response (four gsuite connectors plus a system
device, no <enabled> and no <backup-retention>), with names and GUIDs replaced. The /jobs,
/attributes and /resources shapes follow the published Relax NG schemas; no live body has been
seen for them yet. Each check has a passing body, a flip that must fail, and the fail-closed
inputs (empty, None, "{}", an error envelope, raw XML, a partial per-connector read)."""
import copy
import importlib.util
import pathlib

import pytest

HERE = pathlib.Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location("keepit_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def connector(i, kind="gsuite", retention=None):
    c = {"guid": "aaaaa%d-bbbbbb-cccccc" % i, "created": "2026-01-0%dT10:00:00Z" % (i + 1),
         "name": "Workspace Backup %d" % i, "type": kind, "uri": "None", "login": "None",
         "password": "<redacted>", "backup-retention-updated": "2026-01-19T13:32:50Z"}
    if retention is not None:
        c["backup-retention"] = retention
    return c


def devices(n=4, **kw):
    return {"devices": {"cloud": [connector(i, **kw) for i in range(n)],
                        "system": {"guid": "sys000-000000-000000", "created": "2026-09-21T10:44:55Z", "name": "SupportData"}}}


def job(state="successful", kind="backup", i=0):
    j = {"guid": "job%d" % i, "description": "Backup", "type": kind, "priority": "5", "active": "false",
         "start": "2026-09-24T01:00:00Z", "scheduled": "2026-09-24T00:59:00Z", "started": "2026-09-24T01:00:05Z",
         "state": state}
    if state == "successful":
        j["succeeded"] = "2026-09-24T01:20:00Z"
    elif state in ("unsuccessful", "incomplete"):
        j["failed"] = "2026-09-24T01:20:00Z"
    elif state == "cancelled":
        j["cancelled"] = "2026-09-24T01:20:00Z"
    return j


def jobs_body(states):
    items = [job(s, i=i) for i, s in enumerate(states)]
    if not items:
        return {"jobs": None}
    return {"jobs": {"job": items[0] if len(items) == 1 else items}}


def with_jobs(per_connector):
    d = devices(len(per_connector))
    d["deviceJobs"] = [jobs_body(s) for s in per_connector]
    return d


def resources(**limits):
    return {"resources": {"resource": [
        {"evaluated": "2026-09-25T00:00:00Z", "name": k.replace("_", "-"), "type": "duration", "limit": v}
        for k, v in limits.items()]}}


FAIL_CLOSED = [{}, None, "{}", "", {"error": True, "statusCode": 401, "message": "Unauthorized"},
               "<devices><cloud/></devices>", {"devices": None}]

HEALTHY = with_jobs([["successful"] * 3, ["successful"] * 2, ["successful"], ["successful", "successful"]])
ONE_FAIL = with_jobs([["successful"] * 3, ["successful", "unsuccessful"], ["successful"], ["successful"]])


# ---- job history -------------------------------------------------------------------------

def test_failed_jobs_count_real_shape_and_flip():
    t = load("failedbackupjobscount")
    assert t(HEALTHY)["failedBackupJobsCount"] == 0
    assert t(ONE_FAIL)["failedBackupJobsCount"] == 1
    incomplete = with_jobs([["incomplete"], ["successful"], ["successful"], ["successful"]])
    assert t(incomplete)["failedBackupJobsCount"] == 1
    assert t({"apiResponse": ONE_FAIL})["failedBackupJobsCount"] == 1


def test_success_rate_and_flip():
    t = load("backupsuccessratepercentage")
    assert t(HEALTHY)["backupSuccessRatePercentage"] == 100.0
    low = with_jobs([["successful", "unsuccessful"], ["unsuccessful"], ["successful"], ["cancelled"]])
    assert t(low)["backupSuccessRatePercentage"] == 40.0


def test_stale_connectors_and_flip():
    t = load("staleprotectionjobscount")
    assert t(HEALTHY)["staleProtectionJobsCount"] == 0
    stale = with_jobs([["successful"], [], ["unsuccessful"], ["successful"]])
    out = t(stale)
    assert out["staleProtectionJobsCount"] == 2
    assert len(out["staleConnectors"]) == 2


def test_job_log_accessible_and_flip():
    t = load("isjobexecutionlogaccessible")
    assert t(HEALTHY)["isJobExecutionLogAccessible"] is True
    assert t(with_jobs([["successful"], [], ["successful"], ["successful"]]))["isJobExecutionLogAccessible"] is False
    only_restores = with_jobs([["successful"]] * 4)
    for body in only_restores["deviceJobs"]:
        body["jobs"]["job"]["type"] = "restore"
    assert t(only_restores)["isJobExecutionLogAccessible"] is False


def test_single_connector_is_a_dict_not_a_list():
    one = {"devices": {"cloud": connector(0)}, "deviceJobs": jobs_body(["successful", "unsuccessful"])}
    assert load("failedbackupjobscount")(one)["failedBackupJobsCount"] == 1
    assert load("backupsuccessratepercentage")(one)["backupSuccessRatePercentage"] == 50.0


@pytest.mark.parametrize("name,key", [("failedbackupjobscount", "failedBackupJobsCount"),
                                      ("backupsuccessratepercentage", "backupSuccessRatePercentage"),
                                      ("staleprotectionjobscount", "staleProtectionJobsCount")])
def test_job_counts_fail_closed_to_none(name, key):
    t = load(name)
    for body in FAIL_CLOSED + [devices(4)]:
        assert t(body)[key] is None, body
    partial = copy.deepcopy(HEALTHY)
    partial["deviceJobs"] = partial["deviceJobs"][:3]
    assert t(partial)[key] is None
    no_connectors = {"devices": None, "deviceJobs": []}
    assert t(no_connectors)[key] is None


def test_counts_need_a_finished_job():
    nothing_finished = with_jobs([[], [], [], []])
    assert load("failedbackupjobscount")(nothing_finished)["failedBackupJobsCount"] is None
    assert load("backupsuccessratepercentage")(nothing_finished)["backupSuccessRatePercentage"] is None


def test_job_log_fail_closed():
    t = load("isjobexecutionlogaccessible")
    for body in FAIL_CLOSED + [devices(4)]:
        assert t(body)["isJobExecutionLogAccessible"] is False, body


# ---- retention ---------------------------------------------------------------------------

def retention_body(generic="P1Y", gsuite=None, own=None):
    d = devices(4, retention=own)
    limits = {"generic_snapshot_retention": generic}
    if gsuite is not None:
        limits["gsuite_snapshot_retention"] = gsuite
    d.update(resources(**limits))
    return d


def test_deletion_retention_real_shape_and_flip():
    t = load("isdeletionretentionperiodenforced")
    assert t(retention_body("P1Y"))["isDeletionRetentionPeriodEnforced"] is True
    assert t(retention_body("P30D"))["isDeletionRetentionPeriodEnforced"] is True
    assert t(retention_body("P14D"))["isDeletionRetentionPeriodEnforced"] is False
    # the connector-type resource beats the generic one, the connector's own value beats both
    assert t(retention_body("P1Y", gsuite="P7D"))["isDeletionRetentionPeriodEnforced"] is False
    assert t(retention_body("P7D", gsuite="P3M"))["isDeletionRetentionPeriodEnforced"] is True
    assert t(retention_body("P1Y", own="P1W"))["isDeletionRetentionPeriodEnforced"] is False


def test_infinite_retention_and_flip():
    t = load("isinfinitecloudretentionenabled")
    assert t(retention_body("P99Y"))["isInfiniteCloudRetentionEnabled"] is True
    assert t(retention_body("P1Y"))["isInfiniteCloudRetentionEnabled"] is True
    assert t(retention_body("P6M"))["isInfiniteCloudRetentionEnabled"] is False


@pytest.mark.parametrize("name,key", [("isdeletionretentionperiodenforced", "isDeletionRetentionPeriodEnforced"),
                                      ("isinfinitecloudretentionenabled", "isInfiniteCloudRetentionEnabled")])
def test_retention_fail_closed(name, key):
    t = load(name)
    for body in FAIL_CLOSED + [devices(4), resources(generic_snapshot_retention="P99Y")]:
        assert t(body)[key] is False, body
    for odd in ["unlimited", "P0D", "365", "", "P", "PT"]:
        assert t(retention_body(odd))[key] is False, odd
    no_retention = devices(4)
    no_retention.update(resources(backup_interval="PT4H"))
    assert t(no_retention)[key] is False
    assert t({"devices": None, "resources": None})[key] is False


# ---- multi-geo ---------------------------------------------------------------------------

def test_data_sovereignty_and_flip():
    t = load("isdatasovereigntyregionenforced")
    body = {"resources": {"resource": [{"name": "multigeo", "type": "boolean", "limit": "false"},
                                       {"name": "devices", "type": "integer", "limit": "10", "usage": "4"}]}}
    assert t(body)["isDataSovereigntyRegionEnforced"] is True
    flipped = copy.deepcopy(body)
    flipped["resources"]["resource"][0]["limit"] = "true"
    assert t(flipped)["isDataSovereigntyRegionEnforced"] is False
    absent = {"resources": {"resource": {"name": "devices", "type": "integer", "limit": "10"}}}
    assert t(absent)["isDataSovereigntyRegionEnforced"] is False
    for body in FAIL_CLOSED + [{"resources": None}]:
        assert t(body)["isDataSovereigntyRegionEnforced"] is False, body


# ---- schedule ----------------------------------------------------------------------------

def attrs(**kv):
    items = [{"name": k, "value": v} for k, v in kv.items()]
    if not items:
        return {"attributes": None}
    return {"attributes": {"attribute": items[0] if len(items) == 1 else items}}


def schedule_body(per_connector, product_interval="PT8H"):
    d = devices(len(per_connector))
    d["deviceAttributes"] = per_connector
    limits = {} if product_interval is None else {"backup_interval": product_interval}
    d.update(resources(**limits))
    return d


def test_schedule_and_flip():
    t = load("isbackuptypesscheduled")
    assert t(schedule_body([attrs(), attrs(backup_config="{}"), attrs(), attrs()]))["isBackupTypesScheduled"] is True
    assert t(schedule_body([attrs(backup_interval="PT4H")] * 4, product_interval=None))["isBackupTypesScheduled"] is True
    off = [attrs(), attrs(disable_auto_backup="true"), attrs(), attrs()]
    assert t(schedule_body(off))["isBackupTypesScheduled"] is False
    assert t(schedule_body([attrs()] * 4, product_interval=None))["isBackupTypesScheduled"] is False
    odd = [attrs(disable_auto_backup="maybe")] + [attrs()] * 3
    assert t(schedule_body(odd))["isBackupTypesScheduled"] is False


def test_schedule_fail_closed():
    t = load("isbackuptypesscheduled")
    for body in FAIL_CLOSED + [devices(4)]:
        assert t(body)["isBackupTypesScheduled"] is False, body
    partial = schedule_body([attrs()] * 3)
    partial["devices"]["cloud"].append(connector(9))
    assert t(partial)["isBackupTypesScheduled"] is False
