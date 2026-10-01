"""NetBackup isBackupTested / isBackupTypesScheduled / isBackupEncrypted.

Bodies are shaped after the public NetBackup 11.0 API reference only
(sort.veritas.com/public/documents/nbu/11.0/windowsandunix/productguides/html/: admin GET /admin/jobs,
security GET /security/status). Real verdicts on complete reads; None (not False) on empty, partial,
error and unrelated bodies.
"""
import importlib.util
import os
from datetime import datetime, timedelta, timezone

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name):
    spec = importlib.util.spec_from_file_location("netbackup_gaps_" + name, os.path.join(HERE, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def value(key, payload):
    return load(key.lower())(payload)["transformedResponse"][key]


def wrap(inner):
    return {"data": {"apiResponse": inner}, "validation": {"status": "skipped", "errors": [], "warnings": []}}


NO_EVIDENCE = [{}, "", None, {"status": 401, "message": "Unauthorized"}, {"error": "invalid_token"},
               {"errorCode": 8000, "errorMessage": "User does not have permission(s) to perform the requested operation."},
               {"foo": "bar"}, {"meta": {"page": 1}, "links": {}}]


def ago(days):
    return (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def job(i, job_type, days, status=0, sub="SCHEDULED"):
    return {"type": "job", "id": str(i), "attributes": {
        "jobId": i, "parentJobId": 0, "jobType": job_type, "jobSubType": sub, "policyName": "prod-" + str(i % 2),
        "scheduleType": "FULL", "scheduleName": "daily", "clientName": "client" + str(i), "status": status,
        "state": "DONE", "startTime": ago(days), "endTime": ago(days)}}


def jobs(items, next_page=False):
    meta = {"pagination": {"offset": 0, "limit": 100, "count": len(items)}}
    if next_page:
        meta["pagination"]["next"] = 100
    return wrap({"data": items, "meta": meta, "links": {}})


# ---- isBackupTested ---------------------------------------------------------------------------

def test_restore_tested():
    assert value("isBackupTested", jobs([job(1, "RESTORE", 10, sub="IMMEDIATE")])) is True
    assert value("isBackupTested", jobs([job(1, "RESTORE", 10, status=1)])) is True


def test_restore_not_tested():
    assert value("isBackupTested", jobs([])) is False
    assert value("isBackupTested", jobs([job(1, "RESTORE", 120)])) is False
    assert value("isBackupTested", jobs([job(1, "RESTORE", 10, status=150)])) is False


def test_restore_partial_miss_is_none():
    assert value("isBackupTested", jobs([job(1, "RESTORE", 10, status=2)], next_page=True)) is None


# ---- isBackupTypesScheduled -------------------------------------------------------------------

def test_scheduled_backups_running():
    assert value("isBackupTypesScheduled", jobs([job(1, "BACKUP", 1), job(2, "BACKUP", 2, sub="IMMEDIATE")])) is True


def test_no_scheduled_backups():
    assert value("isBackupTypesScheduled", jobs([job(1, "BACKUP", 1, sub="IMMEDIATE"), job(2, "BACKUP", 2, sub="USERBACKUP")])) is False
    assert value("isBackupTypesScheduled", jobs([job(1, "BACKUP", 10)])) is False
    assert value("isBackupTypesScheduled", jobs([job(1, "BACKUP", 1, status=2)])) is False


def test_scheduled_partial_miss_is_none():
    assert value("isBackupTypesScheduled", jobs([job(1, "BACKUP", 1, sub="IMMEDIATE")], next_page=True)) is None


# ---- isBackupEncrypted ------------------------------------------------------------------------

def status(pct, total=3):
    setting = {"currentConfigState": pct, "baseConfigState": 100, "configWeightage": 5,
               "totalEncryptionSupportedStorages": total, "isBaselineSet": False, "recommendedValues": [100]}
    return wrap({"data": {"type": "securityStatus", "id": "status", "attributes": {
        "platformRiskScore": 20, "securitySettingsDetail": {"backupStoragePercentageWithEncryptionEnabled": setting,
                                                            "mfaEnforced": {"currentConfigState": "ENABLED"}}}}})


def test_encrypted():
    assert value("isBackupEncrypted", status(100)) is True


def test_not_encrypted():
    assert value("isBackupEncrypted", status(66.67)) is False
    assert value("isBackupEncrypted", status(0)) is False


def test_encrypted_none_without_storage_or_setting():
    assert value("isBackupEncrypted", status(0, total=0)) is None
    body = status(100)
    del body["data"]["apiResponse"]["data"]["attributes"]["securitySettingsDetail"]["backupStoragePercentageWithEncryptionEnabled"]
    assert value("isBackupEncrypted", body) is None


@pytest.mark.parametrize("key", ["isBackupTested", "isBackupTypesScheduled", "isBackupEncrypted"])
@pytest.mark.parametrize("body", NO_EVIDENCE)
def test_none_on_no_evidence(key, body):
    assert value(key, body) is None
