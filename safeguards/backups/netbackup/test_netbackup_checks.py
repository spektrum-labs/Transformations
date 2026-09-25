"""NetBackup REST API checks (GET /admin/jobs, GET /security/status). JSON:API bodies shaped per the published
NetBackup 11.x OpenAPI specs, synthetic values; no customer has connected yet. Runs in the Token-Service sandbox
replica when RestrictedPython is installed, else plain Python. Each check has a pass, a flip, and the fail-closed battery."""
import copy
import importlib.util
import pathlib
from datetime import datetime, timedelta, timezone

import pytest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]
try:
    import RestrictedPython  # noqa: F401
    spec = importlib.util.spec_from_file_location("restricted_sandbox_netbackup", ROOT / "tools" / "restricted_sandbox.py")
    sandbox = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sandbox)
    load_code = sandbox.load
except ImportError:
    def load_code(code, filename):
        ns = {"__name__": "netbackup_" + filename}
        exec(compile(code, filename, "exec"), ns)
        return ns


def run(key, body):
    return load_code((HERE / (key.lower() + ".py")).read_text(), key)["transform"](body)[key]


def ts(days):
    return (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def job(i, status=0, days=1, jtype="BACKUP", state="DONE"):
    return {"type": "job", "id": str(i), "attributes": {"jobId": i, "jobType": jtype, "state": state, "status": status,
            "startTime": ts(days), "endTime": ts(days), "policyName": "pol", "clientName": "c%d" % i}}


def jobs(items, nxt=None):
    d = {"data": items, "meta": {"pagination": {"limit": 100}}}
    if nxt:
        d["meta"]["pagination"]["next"] = nxt
    return d


def status(**over):
    detail = {"ssoEnabled": {"currentConfigState": True}, "mfaEnforced": {"currentConfigState": True},
              "backupAnomalyDetection": {"currentConfigState": 2},
              "isImmutableBackupStorageConfigured": {"currentConfigState": True, "totalImmutableBackupStorages": 3, "totalActiveBackupStorages": 3},
              "clientPercentageWithLatestNbuVersion": {"currentConfigState": 100, "totalHosts": 40}}
    for k, v in over.items():
        if v is None:
            detail.pop(k)
        else:
            detail[k] = v
    return {"data": {"type": "securityStatus", "id": "1", "attributes": {"templateVersion": 1, "platformRiskScore": 20, "securitySettingsDetail": detail}}}


GOOD = jobs([job(1), job(2), job(3, status=1), job(4, status=58), job(5, days=10, status=96)])
FAIL_CLOSED = [{}, None, "{}", "", {"error": True, "statusCode": 401}, {"errorCode": 8000, "errorMessage": "x"},
               {"hello": "world"}, []]
ALL = ["failedBackupJobsCount", "backupSuccessRatePercentage", "isBackupEnabled", "isSSOEnabled", "isMFAEnforcedForUsers",
       "isRansomwareDetectionEnabled", "isBackupImmutable", "isBackupClientVersionCurrent"]


@pytest.mark.parametrize("key", ALL)
@pytest.mark.parametrize("body", FAIL_CLOSED, ids=range(len(FAIL_CLOSED)))
def test_fail_closed(key, body):
    assert run(key, copy.deepcopy(body)) in (None, False)


def test_jobs():
    assert run("failedBackupJobsCount", GOOD) == 1
    assert run("failedBackupJobsCount", jobs([job(1), job(2)])) == 0
    assert run("failedBackupJobsCount", jobs([job(1)] * 100, nxt="abc")) is None
    assert run("failedBackupJobsCount", jobs([job(1), job(2, days=9)], nxt="abc")) == 0
    assert run("failedBackupJobsCount", jobs([job(1, days=9)])) is None
    assert run("failedBackupJobsCount", jobs([job(1), {"type": "job", "id": "2"}])) is None
    assert run("backupSuccessRatePercentage", GOOD) == 50.0
    assert run("backupSuccessRatePercentage", jobs([job(1, jtype="RESTORE")])) is None
    assert run("isBackupEnabled", GOOD) is True
    assert run("isBackupEnabled", {"response": GOOD}) is True
    assert run("isBackupEnabled", jobs([job(1, status=58)])) is False
    assert run("isBackupEnabled", jobs([job(1, state="ACTIVE")])) is False


def test_status():
    s = status()
    for k in ["isSSOEnabled", "isMFAEnforcedForUsers", "isRansomwareDetectionEnabled", "isBackupImmutable", "isBackupClientVersionCurrent"]:
        assert run(k, s) is True, k
    assert run("isSSOEnabled", status(ssoEnabled={"currentConfigState": False})) is False
    assert run("isSSOEnabled", status(ssoEnabled=None)) is False
    assert run("isMFAEnforcedForUsers", status(mfaEnforced={"currentConfigState": False})) is False
    assert run("isRansomwareDetectionEnabled", status(backupAnomalyDetection={"currentConfigState": 1})) is False
    assert run("isRansomwareDetectionEnabled", status(backupAnomalyDetection={"currentConfigState": 3})) is False
    assert run("isBackupImmutable", status(isImmutableBackupStorageConfigured={"currentConfigState": True, "totalImmutableBackupStorages": 1, "totalActiveBackupStorages": 3})) is False
    assert run("isBackupImmutable", status(isImmutableBackupStorageConfigured={"currentConfigState": False, "totalImmutableBackupStorages": 0, "totalActiveBackupStorages": 0})) is False
    assert run("isBackupClientVersionCurrent", status(clientPercentageWithLatestNbuVersion={"currentConfigState": 87.5, "totalHosts": 40})) is False
    assert run("isBackupClientVersionCurrent", status(clientPercentageWithLatestNbuVersion={"currentConfigState": 100, "totalHosts": 0})) is False
