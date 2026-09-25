"""Commvault (Command Center REST API) checks, on bodies shaped as Commvault documents them.

No live Commvault body has been seen yet: the one customer with saved credentials does not
authenticate today. Shapes follow the GET Job reference (documentation.commvault.com 11.40),
Commvault's published V4 OpenAPI 3 spec (Commvault/CVPowershellSDKV2 OpenAPI3.yaml) and
cvpysdk (two-factor authentication). Each check has a passing body, a flip that must fail, and
the fail-closed inputs (empty, None, "{}", "", an Integration-Service error envelope, a
Commvault errorCode body, XML, and a partial or paginated read)."""
import copy
import importlib.util
import pathlib

import pytest

HERE = pathlib.Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location("commvault_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def job(status="Completed", i=0, kind="Backup"):
    return {"jobSummary": {"jobId": 1000 + i, "jobType": kind, "status": status, "backupLevelName": "Incremental",
                           "jobStartTime": 1790000000 + i, "jobEndTime": 1790000600 + i, "lastUpdateTime": 1790000600 + i,
                           "subclient": {"clientName": "fs%02d" % i, "subclientName": "default", "backupsetName": "defaultBackupSet"},
                           "destClientName": "fs%02d" % i, "percentComplete": 100}}


def jobs(statuses, kind="Backup", total=None):
    items = [job(s, i, kind) for i, s in enumerate(statuses)]
    return {"totalRecordsWithoutPaging": len(items) if total is None else total, "jobs": items}


ERR_IS = {"error": True, "statusCode": 401, "message": "Unauthorized"}
ERR_CV = {"errorMessage": "Access denied", "errorCode": 5}
EMPTYISH = [{}, None, "{}", "", ERR_IS, ERR_CV, "<JobManager_JobListResponse/>", {"errList": [{"errorCode": 2, "errLogMessage": "x"}]}]

HEALTHY = jobs(["Completed"] * 8 + ["Completed w/ one or more warnings"] * 2)
ONE_FAIL = jobs(["Completed"] * 8 + ["Failed", "Completed w/ one or more errors"])
PAGED = jobs(["Completed"] * 3, total=250)


# ---- job history -------------------------------------------------------------------------

def test_failed_count():
    t = load("failedbackupjobscount")
    assert t(HEALTHY)["failedBackupJobsCount"] == 0
    assert t(ONE_FAIL)["failedBackupJobsCount"] == 2
    assert t(jobs(["Killed", "Committed", "Failed to Start"]))["failedBackupJobsCount"] == 3
    assert t(jobs([]))["failedBackupJobsCount"] is None          # nothing finished: zero is not proven
    assert t(PAGED)["failedBackupJobsCount"] is None             # unread pages
    assert t(jobs(["Completed", "Something new"]))["failedBackupJobsCount"] is None
    for bad in EMPTYISH:
        assert t(bad)["failedBackupJobsCount"] is None


def test_success_rate():
    t = load("backupsuccessratepercentage")
    assert t(HEALTHY)["backupSuccessRatePercentage"] == 100.0
    assert t(ONE_FAIL)["backupSuccessRatePercentage"] == 80.0
    assert t({"apiResponse": HEALTHY})["backupSuccessRatePercentage"] == 100.0
    assert t(PAGED)["backupSuccessRatePercentage"] is None
    assert t(jobs([]))["backupSuccessRatePercentage"] is None
    for bad in EMPTYISH:
        assert t(bad)["backupSuccessRatePercentage"] is None


def test_job_log_accessible():
    t = load("isjobexecutionlogaccessible")
    assert t(HEALTHY)["isJobExecutionLogAccessible"] is True
    broken = copy.deepcopy(HEALTHY)
    del broken["jobs"][3]["jobSummary"]["jobEndTime"]
    del broken["jobs"][3]["jobSummary"]["lastUpdateTime"]
    assert t(broken)["isJobExecutionLogAccessible"] is False
    assert t(jobs([]))["isJobExecutionLogAccessible"] is False
    assert t(PAGED)["isJobExecutionLogAccessible"] is False
    for bad in EMPTYISH:
        assert t(bad)["isJobExecutionLogAccessible"] is False


def test_backup_enabled():
    t = load("isbackupenabled")
    assert t(HEALTHY)["isBackupEnabled"] is True
    assert t(jobs(["Failed", "Killed"]))["isBackupEnabled"] is False
    assert t({"totalRecordsWithoutPaging": 0})["isBackupEnabled"] is False
    assert t(PAGED)["isBackupEnabled"] is False
    for bad in EMPTYISH:
        assert t(bad)["isBackupEnabled"] is False


@pytest.mark.parametrize("name,key", [("isbackuptested", "isBackupTested"), ("arebackupstested", "areBackupsTested")])
def test_restore_tested(name, key):
    t = load(name)
    assert t(jobs(["Failed", "Completed"], kind="Restore"))[key] is True
    assert t(jobs(["Failed", "Killed"], kind="Restore"))[key] is False
    assert t(jobs([], kind="Restore"))[key] is False
    assert t(jobs(["Completed"], kind="Restore", total=5))[key] is False
    for bad in EMPTYISH:
        assert t(bad)[key] is False


# ---- plans -------------------------------------------------------------------------------

def plan(i, rpo=240, status="ENABLED", kind="Server", entities=3):
    return {"plan": {"id": i, "name": "Plan%d" % i}, "planType": kind, "associatedEntities": entities, "RPO": rpo,
            "numberOfCopies": 2, "status": status}


def plans(items, count=None):
    return {"plans": items, "plansCount": len(items) if count is None else count}


PLANS_OK = plans([plan(1), plan(2, rpo=1440), plan(3, kind="Laptop", rpo=0), plan(4, rpo=0, entities=0)])


def test_backup_types_scheduled():
    t = load("isbackuptypesscheduled")
    assert t(PLANS_OK)["isBackupTypesScheduled"] is True
    assert t(plans([plan(1), plan(2, status="BACKUP_DISABLED")]))["isBackupTypesScheduled"] is False
    assert t(plans([plan(1), plan(2, rpo=0)]))["isBackupTypesScheduled"] is False
    assert t(plans([plan(3, kind="Laptop")]))["isBackupTypesScheduled"] is False
    assert t(plans([plan(1)], count=40))["isBackupTypesScheduled"] is False
    for bad in EMPTYISH:
        assert t(bad)["isBackupTypesScheduled"] is False


def test_rpo_within_sla():
    t = load("isprotectionpolicyrpowithinsla")
    assert t(PLANS_OK)["isProtectionPolicyRPOWithinSLA"] is True
    assert t(plans([plan(1), plan(2, rpo=2880)]))["isProtectionPolicyRPOWithinSLA"] is False
    assert t(plans([]))["isProtectionPolicyRPOWithinSLA"] is False
    for bad in EMPTYISH:
        assert t(bad)["isProtectionPolicyRPOWithinSLA"] is False


def test_m365_coverage():
    t = load("ism365backupcoverageenabled")
    key = "isM365BackupCoverageEnabled"
    assert t(plans([plan(1), plan(5, kind="Office365", rpo=0, entities=120)]))[key] is True
    assert t(plans([plan(1), plan(5, kind="Office365", entities=0)]))[key] is False
    assert t(plans([plan(5, kind="Office365", status="DISABLED", entities=120)]))[key] is False
    assert t(plans([plan(1)]))[key] is False
    assert t(plans([plan(5, kind="Office365", entities=9)], count=30))[key] is False
    for bad in EMPTYISH:
        assert t(bad)[key] is False


# ---- storage -----------------------------------------------------------------------------

def disk_list(*pairs):
    return {"diskStorage": [{"id": i + 1, "name": "Disk%d" % i, "storagePoolType": "DEDUPLICATION", "status": "Online",
                             "capacity": c, "freeSpace": f} for i, (c, f) in enumerate(pairs)]}


def test_local_utilisation():
    t = load("localstorageutilizationpercentage")
    assert t(disk_list((1000, 250), (1000, 250)))["localStorageUtilizationPercentage"] == 75.0
    assert t(disk_list((1000, 50)))["localStorageUtilizationPercentage"] == 95.0
    assert t(disk_list())["localStorageUtilizationPercentage"] is None
    assert t({"diskStorage": [{"name": "x", "capacity": None, "freeSpace": 3}]})["localStorageUtilizationPercentage"] is None
    for bad in EMPTYISH:
        assert t(bad)["localStorageUtilizationPercentage"] is None


def detail(i, encrypt=True, cipher="AES", length=256):
    return {"id": i, "name": "Pool%d" % i, "general": {"capacity": 100, "freeSpace": 50},
            "encryption": {"encrypt": encrypt, "cipher": cipher, "keyLength": length, "keyProvider": {"id": 1, "name": "Built-in"}}}


def storage(disk, cloud):
    body = {"diskStorage": [{"id": d["id"], "name": d["name"]} for d in disk],
            "cloudStorage": [{"id": c["id"], "name": c["name"]} for c in cloud]}
    if disk:
        body["diskStorageDetails"] = disk
    if cloud:
        body["cloudStorageDetails"] = cloud
    return body


GOOD_STORAGE = storage([detail(1), detail(2)], [detail(3), detail(4)])


def test_backup_encrypted():
    t = load("isbackupencrypted")
    assert t(GOOD_STORAGE)["isBackupEncrypted"] is True
    assert t(storage([detail(1), detail(2, encrypt=False)], [detail(3)]))["isBackupEncrypted"] is False
    assert t(storage([], []))["isBackupEncrypted"] is False
    partial = copy.deepcopy(GOOD_STORAGE)
    partial["diskStorageDetails"] = partial["diskStorageDetails"][:1]
    assert t(partial)["isBackupEncrypted"] is False
    missing = copy.deepcopy(GOOD_STORAGE)
    del missing["cloudStorageDetails"]
    assert t(missing)["isBackupEncrypted"] is False
    errored = copy.deepcopy(GOOD_STORAGE)
    errored["cloudStorageDetails"][1] = ERR_CV
    assert t(errored)["isBackupEncrypted"] is False
    for bad in EMPTYISH:
        assert t(bad)["isBackupEncrypted"] is False


def test_cloud_tier_encryption():
    t = load("iscloudtierencryptionenabled")
    assert t(GOOD_STORAGE)["isCloudTierEncryptionEnabled"] is True
    assert t(storage([detail(1, encrypt=False)], [detail(3)]))["isCloudTierEncryptionEnabled"] is True   # disk is not the cloud tier
    assert t(storage([detail(1)], [detail(3, encrypt=False)]))["isCloudTierEncryptionEnabled"] is False
    assert t(storage([detail(1)], []))["isCloudTierEncryptionEnabled"] is False
    for bad in EMPTYISH:
        assert t(bad)["isCloudTierEncryptionEnabled"] is False


def test_external_target_aes256():
    t = load("isexternaltargetencryptionaes256")
    assert t(GOOD_STORAGE)["isExternalTargetEncryptionAES256"] is True
    assert t(storage([], [detail(3), detail(4, length=128)]))["isExternalTargetEncryptionAES256"] is False
    assert t(storage([], [detail(3, cipher="Twofish")]))["isExternalTargetEncryptionAES256"] is False
    assert t(storage([detail(1)], []))["isExternalTargetEncryptionAES256"] is False
    for bad in EMPTYISH:
        assert t(bad)["isExternalTargetEncryptionAES256"] is False


# ---- identity, syslog, licence, 2FA ------------------------------------------------------

def test_sso():
    t = load("isssoenabled")
    ok = {"identityServers": [{"id": 1, "name": "corp.local", "type": "ACTIVE_DIRECTORY", "configured": True},
                              {"id": 2, "name": "Okta", "type": "SAML", "samlType": "OKTA", "configured": True}]}
    assert t(ok)["isSSOEnabled"] is True
    ad_only = {"identityServers": ok["identityServers"][:1]}
    assert t(ad_only)["isSSOEnabled"] is False
    unconfigured = copy.deepcopy(ok)
    unconfigured["identityServers"][1]["configured"] = False
    assert t(unconfigured)["isSSOEnabled"] is False
    assert t({"identityServers": []})["isSSOEnabled"] is False
    for bad in EMPTYISH:
        assert t(bad)["isSSOEnabled"] is False


SYSLOG = {"hostname": "siem.example.com", "port": 6514, "enabled": True, "secureMessaging": True,
          "forwardToSyslog": {"alerts": True, "audit": True, "events": False}}


def test_audit_forwarding():
    t = load("isauditlogforwardingenabled")
    assert t(SYSLOG)["isAuditLogForwardingEnabled"] is True
    for field, value in (("enabled", False), ("hostname", ""), ("forwardToSyslog", {"audit": False, "alerts": True})):
        b = copy.deepcopy(SYSLOG)
        b[field] = value
        assert t(b)["isAuditLogForwardingEnabled"] is False
    for bad in EMPTYISH:
        assert t(bad)["isAuditLogForwardingEnabled"] is False


def test_licence():
    t = load("confirmedlicensepurchased")
    lic = {"commCellId": 2, "edition": "Commvault", "licenseMode": "PRODUCTION", "expiryDate": 4102444800}
    assert t(lic)["confirmedLicensePurchased"] is True
    assert t(dict(lic, expiryDate=0))["confirmedLicensePurchased"] is True
    assert t(dict(lic, licenseMode="EVALUATION"))["confirmedLicensePurchased"] is False
    assert t(dict(lic, expiryDate=1600000000))["confirmedLicensePurchased"] is False
    for bad in EMPTYISH:
        assert t(bad)["confirmedLicensePurchased"] is False


def test_mfa():
    t = load("ismfaenforcedforusers")
    ok = {"twoFactorAuthenticationInfo": {"mode": 1, "userGroups": []}, "error": {"errorCode": 0}}
    assert t(ok)["isMFAEnforcedForUsers"] is True
    assert t({"twoFactorAuthenticationInfo": {"mode": 2, "userGroups": [{"userGroupName": "master"}]}})["isMFAEnforcedForUsers"] is False
    assert t({"twoFactorAuthenticationInfo": {"mode": 0}})["isMFAEnforcedForUsers"] is False
    assert t({"twoFactorAuthenticationInfo": {"mode": 1}, "error": {"errorCode": 5, "errorString": "denied"}})["isMFAEnforcedForUsers"] is False
    for bad in EMPTYISH:
        assert t(bad)["isMFAEnforcedForUsers"] is False


# ---- alerts ------------------------------------------------------------------------------

def alert_detail(i, criteria="Backup Job Failed", channels=("EMAIL",), to=({"id": 1, "name": "ops", "type": "USER_GROUP"},),
                 webhook=None, associations=({"id": 0, "name": "All servers", "type": "ALL_SERVERS"},)):
    rec = {"to": list(to), "cc": [], "bcc": []}
    if webhook is not None:
        rec["webHookId"] = webhook
    return {"id": i, "name": "Alert%d" % i,
            "alertSummary": {"type": {"id": 3, "name": "Data Protection"}, "category": {"id": 1, "name": "Job Management"},
                             "criteria": {"id": 1, "name": criteria}},
            "associations": list(associations), "alertTarget": {"sendAlertTo": list(channels), "recipients": rec}}


def alerts(details, enabled=None):
    enabled = enabled or {}
    return {"alertDefinitions": [{"id": d["id"], "name": d["name"], "type": "Data Protection", "enabled": enabled.get(d["id"], True)}
                                 for d in details], "alertDefinitionDetails": details}


def test_failure_notification():
    t = load("ispolicyfailurenotificationconfigured")
    key = "isPolicyFailureNotificationConfigured"
    assert t(alerts([alert_detail(1, criteria="Backup Job Succeeded"), alert_detail(2)]))[key] is True
    assert t(alerts([alert_detail(2, channels=("WEBHOOK",), to=(), webhook=7)]))[key] is True
    assert t(alerts([alert_detail(2)], enabled={2: False}))[key] is False
    assert t(alerts([alert_detail(2, channels=("CONTENT_INDEX", "LIVEFEEDS"))]))[key] is False
    assert t(alerts([alert_detail(2, to=())]))[key] is False
    assert t(alerts([alert_detail(2, associations=())]))[key] is False
    assert t(alerts([alert_detail(1, criteria="Restore Job Failed")]))[key] is False
    partial = alerts([alert_detail(1), alert_detail(2)])
    partial["alertDefinitionDetails"] = partial["alertDefinitionDetails"][:1]
    assert t(partial)[key] is False
    assert t({"alertDefinitions": []})[key] is False
    for bad in EMPTYISH:
        assert t(bad)[key] is False
