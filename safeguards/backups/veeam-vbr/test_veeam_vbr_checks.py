"""Veeam Backup & Replication checks (REST API revision 1.2-rev0). Each file runs in the Token-Service sandbox replica
(tools/restricted_sandbox.py) when RestrictedPython is installed, else as plain Python (CI installs only requirements-test.txt).

Bodies follow the documented response schemas (SessionsResult, JobsResult, JobStatesResult, RepositoriesResult,
RepositoryStatesResult, ScaleOutRepositoriesResult) with synthetic values; no customer has connected yet.
Each check has a passing body, a flip that must fail, and the fail-closed battery.
"""
import copy
import importlib.util
import json
import pathlib
from datetime import datetime, timedelta, timezone

import pytest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]

try:
    import RestrictedPython  # noqa: F401
    spec = importlib.util.spec_from_file_location("restricted_sandbox_veeam_vbr", ROOT / "tools" / "restricted_sandbox.py")
    sandbox = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sandbox)
    load_code = sandbox.load
except ImportError:
    def load_code(code, filename):
        ns = {"__name__": "veeam_vbr_" + filename}
        exec(compile(code, filename, "exec"), ns)
        return ns


def ago(**kw):
    return (datetime.now(timezone.utc) - timedelta(**kw)).strftime("%Y-%m-%dT%H:%M:%S.1234567+00:00")


def load(key):
    return load_code((HERE / (key.lower() + ".py")).read_text(), key)["transform"]


def value(key, body):
    return load(key)(body)["transformedResponse"][key]


def coll(items, total=None):
    return {"data": items, "pagination": {"total": len(items) if total is None else total, "count": len(items), "skip": 0, "limit": 5000}}


def sess(stype, result, hours=5, state="Stopped", name="Job A"):
    return {"id": name + str(hours), "name": name, "jobId": "j1", "sessionType": stype, "state": state,
            "creationTime": ago(hours=hours), "endTime": ago(hours=hours - 1), "result": {"result": result, "message": "", "isCanceled": False}}


BACKUP = coll([sess("BackupJob", "Success", 5), sess("BackupJob", "Success", 30), sess("BackupJob", "Warning", 50),
               sess("BackupJob", "Failed", 70), sess("BackupJob", "None", 1, state="Working")])
BACKUP_CLEAN = coll([sess("BackupJob", "Success", 5), sess("BackupJob", "Success", 30)])
SURE = coll([sess("SureBackup", "Failed", 24 * 20), sess("SureBackup", "Success", 24 * 2)])
SURE_BAD = coll([sess("SureBackup", "Success", 24 * 20), sess("SureBackup", "Failed", 24 * 2)])
CONF = coll([sess("ConfigurationBackup", "Success", 20)])
CONF_BAD = coll([sess("ConfigurationBackup", "Failed", 20)])


def job(name="Job A", repo="r-hard", enc=True, etype="ByUserPassword", mode="Incremental", fulls=False, disabled=False,
        auto=True, health=True, snmp=False, email=True, ntype="UseCustomNotificationSettings"):
    return {"id": name, "name": name, "type": "Backup", "isDisabled": disabled,
            "storage": {"backupRepositoryId": repo, "advancedSettings": {
                "backupModeType": mode,
                "synthenticFulls": {"isEnabled": fulls}, "activeFulls": {"isEnabled": fulls},
                "backupHealth": {"isEnabled": health, "weekly": {"isEnabled": health, "days": ["Saturday"]}, "monthly": {"isEnabled": False}},
                "storageData": {"encryption": {"isEnabled": enc, "encryptionType": etype if enc else None}},
                "notifications": {"sendSNMPNotifications": snmp, "emailNotifications": {
                    "isEnabled": email, "recipients": ["ops@example.com"], "notificationType": ntype,
                    "customNotificationSettings": {"notifyOnSuccess": False, "notifyOnWarning": True, "notifyOnError": True}}}}},
            "schedule": {"runAutomatically": auto, "daily": {"isEnabled": True, "localTime": "22:00", "dailyKind": "Everyday"},
                         "monthly": {"isEnabled": False}, "periodically": {"isEnabled": False}, "continuously": {"isEnabled": False},
                         "afterThisJob": {"isEnabled": False}}}


JOBS = coll([job("Job A"), job("Job B"), job("Old", enc=False, disabled=True, auto=False)])


def jobs_with(**kw):
    return coll([job("Job A"), job("Job B", **kw)])


STATES = coll([
    {"id": "1", "name": "Job A", "type": "Backup", "status": "inactive", "lastRun": ago(hours=10), "lastResult": "Success"},
    {"id": "2", "name": "Job B", "type": "Backup", "status": "running", "lastRun": ago(days=1), "lastResult": "Warning"},
    {"id": "3", "name": "Old", "type": "Backup", "status": "disabled", "lastRun": ago(days=200), "lastResult": "Failed"},
])


def repo_state(name, rtype, cap, used, online=True):
    return {"id": name, "name": name, "type": rtype, "capacityGB": cap, "freeGB": cap - used, "usedSpaceGB": used, "isOnline": online}


RSTATES = coll([repo_state("local1", "WinLocal", 1000.0, 400.0), repo_state("hard1", "LinuxHardened", 1000.0, 200.0),
                repo_state("s3", "AmazonS3", 0.0, 0.0)])

HARD = {"id": "r-hard", "name": "Hardened", "type": "LinuxHardened", "repository": {"makeRecentBackupsImmutableDays": 14}}
S3 = {"id": "r-s3", "name": "S3", "type": "AmazonS3", "bucket": {"bucketName": "b", "immutability": {"isEnabled": True, "daysCount": 30}}}
WIN = {"id": "r-win", "name": "WinLocal", "type": "WinLocal", "repository": {}}
SOBR = {"id": "sobr1", "name": "SOBR", "performanceTier": {"performanceExtents": [{"id": "r-hard", "name": "Hardened", "status": "Normal"}]},
        "capacityTier": {"isEnabled": True, "extents": [{"id": "r-s3"}], "encryption": {"isEnabled": False}}, "archiveTier": {"isEnabled": False}}


def targets(jobs, repos=(HARD, S3, WIN), sobrs=(SOBR,)):
    return {"jobs": coll(list(jobs)), "repositories": coll(list(repos)), "scaleOutRepositories": coll(list(sobrs))}


T_GOOD = targets([job("A", repo="r-hard"), job("B", repo="r-s3"), job("C", repo="sobr1")])
T_MUTABLE = targets([job("A", repo="r-hard"), job("B", repo="r-win")])

# key -> (passing body, expected, failing body, expected)
CASES = {
    "failedBackupJobsCount": (BACKUP_CLEAN, 0, BACKUP, 1),
    "backupSuccessRatePercentage": (BACKUP_CLEAN, 100.0, BACKUP, 50.0),
    "areBackupsTested": (SURE, "Success", SURE_BAD, "Failed"),
    "isBackupTested": (SURE, True, SURE_BAD, False),
    "isServerDbBackupCurrent": (CONF, True, CONF_BAD, False),
    "isBackupEnabled": (JOBS, True, coll([job("A", auto=False), job("B", disabled=True)]), False),
    "isBackupTypesScheduled": (JOBS, True, jobs_with(auto=False), False),
    "isBackupEncrypted": (JOBS, True, jobs_with(enc=False), False),
    "clientAESEncryptionCoveragePercentage": (JOBS, 100.0, jobs_with(enc=False), 50.0),
    "isPrivateEncryptionKeyEnabled": (JOBS, True, jobs_with(etype="ByKms"), False),
    "isForeverIncrementalBackupEnabled": (JOBS, True, jobs_with(fulls=True), False),
    "isInverseChainTechnologyEnabled": (coll([job("A", mode="ReverseIncremental")]), True, JOBS, False),
    "isRestorePointHashVerificationEnabled": (JOBS, True, jobs_with(health=False), False),
    "isPolicyFailureNotificationConfigured": (JOBS, True, jobs_with(email=True, ntype="UseGlobalNotificationSettings"), False),
    "staleProtectionJobsCount": (STATES, 0, coll(STATES["data"][:2] + [
        {"id": "4", "name": "Stuck", "type": "Backup", "status": "inactive", "lastRun": ago(days=12), "lastResult": "Success"}]), 1),
    "localStorageUtilizationPercentage": (RSTATES, 30.0, coll([repo_state("local1", "WinLocal", 100.0, 90.0)]), 90.0),
    "isBackupImmutable": (T_GOOD, True, T_MUTABLE, False),
    "isDeletionRetentionPeriodEnforced": (T_GOOD, True, T_MUTABLE, False),
    "isExternalTargetEncryptionAES256": (T_GOOD, True, targets([job("A", repo="r-s3", enc=False)]), False),
    "isCloudTierEncryptionEnabled": (T_GOOD, True, targets([job("C", repo="sobr1", enc=False)]), False),
}

FALLBACK_NONE = {"failedBackupJobsCount", "backupSuccessRatePercentage", "areBackupsTested",
                 "clientAESEncryptionCoveragePercentage", "staleProtectionJobsCount", "localStorageUtilizationPercentage"}

NOTHING = [{}, None, "{}", "", "not json", [], {"statusCode": 401, "error": "Unauthorized"},
           {"errorCode": "AccessDenied", "message": "Access is denied", "resourceId": None},
           {"error": True, "errorType": "connection_error", "statusCode": 503}, {"data": [], "pagination": {"total": 0}}]


def test_every_file_has_cases():
    files = {p.stem for p in HERE.glob("*.py") if not p.name.startswith("test_")}
    assert files == {k.lower() for k in CASES}


@pytest.mark.parametrize("key", sorted(CASES))
def test_pass_and_flip(key):
    good, want, bad, want_bad = CASES[key]
    assert value(key, good) == want
    assert value(key, json.dumps(good)) == want
    assert value(key, {"apiResponse": good}) == want
    assert value(key, bad) == want_bad


@pytest.mark.parametrize("key", sorted(CASES))
def test_fail_closed(key):
    empty = None if key in FALLBACK_NONE else False
    for body in NOTHING:
        assert value(key, body) == empty, body


@pytest.mark.parametrize("key", sorted(CASES))
def test_unread_page_is_refused(key):
    good = copy.deepcopy(CASES[key][0])
    if "data" in good:
        good["pagination"]["total"] = len(good["data"]) + 1
    else:
        good["repositories"]["pagination"]["total"] += 1
    assert value(key, good) == (None if key in FALLBACK_NONE else False)


def test_session_filters_not_applied_are_refused():
    wrong_type = coll([sess("BackupJob", "Success"), sess("ReplicaJob", "Success")])
    too_old = coll([sess("BackupJob", "Success"), sess("BackupJob", "Failed", hours=24 * 30)])
    for body in (wrong_type, too_old):
        assert value("failedBackupJobsCount", body) is None
        assert value("backupSuccessRatePercentage", body) is None


def test_unresolved_target_is_refused():
    body = targets([job("A", repo="r-missing")])
    for key in ("isBackupImmutable", "isExternalTargetEncryptionAES256", "isCloudTierEncryptionEnabled"):
        assert value(key, body) is False


def test_offline_local_repository_is_unknown():
    assert value("localStorageUtilizationPercentage", coll([repo_state("x", "WinLocal", 100.0, 10.0, online=False)])) is None


def test_no_external_target_is_not_a_pass():
    assert value("isExternalTargetEncryptionAES256", targets([job("A", repo="r-hard")])) is False
    assert value("isCloudTierEncryptionEnabled", targets([job("A", repo="r-hard")])) is False
