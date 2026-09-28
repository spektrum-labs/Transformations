"""Veeam Backup for Microsoft 365 checks (REST API v8). Each file runs in the Token-Service sandbox replica
(tools/restricted_sandbox.py) when RestrictedPython is installed, else as plain Python (CI installs only requirements-test.txt).

Bodies follow the documented v8 response schemas (PageOfRESTJob, PageOfRESTCopyJob, PageOfRESTJobSession,
PageOfRESTBackupRepository, RESTLicense, RESTNotificationEmailSettingsResponse, RESTHistorySettings) with synthetic
values; no customer has connected yet. Each check has a passing body, a flip that must fail, and the fail-closed battery.
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
    spec = importlib.util.spec_from_file_location("restricted_sandbox_veeam_vb365", ROOT / "tools" / "restricted_sandbox.py")
    sandbox = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sandbox)
    load_code = sandbox.load
except ImportError:
    def load_code(code, filename):
        ns = {"__name__": "veeam_vb365_" + filename}
        exec(compile(code, filename, "exec"), ns)
        return ns


def ago(**kw):
    return (datetime.now(timezone.utc) - timedelta(**kw)).strftime("%Y-%m-%dT%H:%M:%S.1234567Z")


def load(key):
    return load_code((HERE / (key.lower() + ".py")).read_text(), key)["transform"]


def value(key, body):
    return load(key)(body)["transformedResponse"][key]


def page(items):
    return {"offset": 0, "limit": 10000, "results": items, "_links": {"self": {"href": "/v8/Jobs?offset=0&limit=10000"}}}


def job(name, enabled=True, kind="Daily", daily="Everyday", every="Hours4", status="Success", last_hours=10):
    return {"id": name, "name": name, "organizationId": "o1", "repositoryId": "r1", "backupType": "EntireOrganization",
            "isEnabled": enabled, "lastStatus": status, "lastRun": ago(hours=last_hours), "lastBackup": ago(hours=last_hours),
            "schedulePolicy": {"type": kind, "dailyType": daily, "dailyTime": "22:00:00", "periodicallyEvery": every, "scheduleEnabled": True}}


def copy_job(name, enabled=True, kind="Immediate", status="Success"):
    return {"id": name, "name": name, "backupJobId": "a", "isEnabled": enabled, "lastStatus": status,
            "schedulePolicy": {"type": kind}}


JOBS = page([job("Mail"), job("Sites", kind="Periodically"), job("Off", enabled=False, kind="ManualOnly", status="Failed")])
INV = {"jobs": JOBS, "copyJobs": page([copy_job("Copy1")])}
INV_BAD = {"jobs": page([job("Mail"), job("Teams", kind="ManualOnly", status="Failed")]), "copyJobs": page([copy_job("Copy1", status="Failed")])}


def sess(status, hours=5):
    return {"id": status + str(hours), "jobId": "a", "jobType": "Backup", "status": status, "creationTime": ago(hours=hours),
            "endTime": ago(hours=hours - 1)}


SESS = page([sess("Success", 5), sess("Success", 30), sess("Running", 1)])
SESS_BAD = page([sess("Success", 5), sess("Warning", 30), sess("Failed", 50), sess("Success", 70)])


def obj_repo(name, enc=True, imm=True, gov=False):
    return {"id": name, "name": name, "objectStorageEncryptionEnabled": enc, "encryptionKeyId": "k" if enc else None,
            "objectStorage": {"id": name, "type": "AmazonS3", "enableImmutability": imm, "enableImmutabilityGovernanceMode": gov,
                              "immutabilityPeriodDays": 30}}


def jet(name, cap, free):
    return {"id": name, "name": name, "path": "E:\\Backups", "capacityBytes": cap, "freeSpaceBytes": free, "objectStorage": None}


REPOS = page([obj_repo("s3a"), obj_repo("s3b"), jet("local", 1000, 700)])
REPOS_BAD = page([obj_repo("s3a"), obj_repo("s3b", enc=False, imm=False, gov=True), jet("local", 1000, 100)])

LICENSE = {"licenseID": "x", "status": "Valid", "type": "Subscription", "licenseExpires": "2027-01-01T00:00:00Z", "totalNumber": 100, "usedNumber": 50}
MAIL = {"enableNotification": True, "notifyOnFailure": True, "notifyOnWarning": True, "notifyOnSuccess": False,
        "to": "ops@example.com;it@example.com", "smtpServer": "smtp.example.com", "port": 587}
HIST = {"keepAllsessions": False, "keeponlyLast": 53}

CASES = {
    "confirmedLicensePurchased": (LICENSE, True, dict(LICENSE, type="Evaluation"), False),
    "isBackupEnabled": (JOBS, True, page([job("Off", enabled=False)]), False),
    "isBackupTypesScheduled": (INV, True, INV_BAD, False),
    "failedBackupJobsCount": (INV, 0, INV_BAD, 2),
    "staleProtectionJobsCount": (JOBS, 0, page([job("Mail"), job("Late", last_hours=24 * 5)]), 1),
    "backupSuccessRatePercentage": (SESS, 100.0, SESS_BAD, 50.0),
    "isBackupEncrypted": (REPOS, True, REPOS_BAD, False),
    "isExternalTargetEncryptionAES256": (REPOS, True, REPOS_BAD, False),
    "isBackupImmutable": (REPOS, True, REPOS_BAD, False),
    "isDataLockComplianceModeEnabled": (REPOS, True, REPOS_BAD, False),
    "localStorageUtilizationPercentage": (REPOS, 30.0, REPOS_BAD, 90.0),
    "isPolicyFailureNotificationConfigured": (MAIL, True, dict(MAIL, notifyOnFailure=False), False),
    "isBackupLoggingEnabled": (HIST, True, {"keepAllsessions": False, "keeponlyLast": 1}, False),
}

FALLBACK_NONE = {"failedBackupJobsCount", "staleProtectionJobsCount", "backupSuccessRatePercentage", "localStorageUtilizationPercentage"}

NOTHING = [{}, None, "{}", "", "not json", [], {"statusCode": 401, "error": "Unauthorized"},
           {"error": True, "errorType": "connection_error", "statusCode": 503}, {"results": [], "limit": 10000}]


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


@pytest.mark.parametrize("key", sorted(k for k in CASES if isinstance(CASES[k][0], dict) and
                                       ("results" in CASES[k][0] or "jobs" in CASES[k][0])))
def test_unread_page_is_refused(key):
    good = copy.deepcopy(CASES[key][0])
    target = good["jobs"] if "jobs" in good else good
    target["_links"]["next"] = {"href": "/v8/Jobs?offset=10000&limit=10000"}
    assert value(key, good) == (None if key in FALLBACK_NONE else False)


def test_session_filters_not_applied_are_refused():
    assert value("backupSuccessRatePercentage", page([sess("Success"), dict(sess("Success"), jobType="Copy")])) is None
    assert value("backupSuccessRatePercentage", page([sess("Success"), sess("Failed", hours=24 * 30)])) is None


def test_governance_mode_is_not_compliance():
    assert value("isDataLockComplianceModeEnabled", page([obj_repo("s3a", gov=True)])) is False
    assert value("isBackupImmutable", page([obj_repo("s3a", gov=True)])) is True


def test_local_only_estate_is_not_an_encryption_pass():
    body = page([jet("local", 1000, 700)])
    for key in ("isBackupEncrypted", "isExternalTargetEncryptionAES256", "isBackupImmutable", "isDataLockComplianceModeEnabled"):
        assert value(key, body) is False
