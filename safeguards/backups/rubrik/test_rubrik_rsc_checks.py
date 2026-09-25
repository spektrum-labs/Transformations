"""Rubrik Security Cloud (GraphQL) checks. Each file runs in the Token-Service sandbox replica (tools/restricted_sandbox.py)
when RestrictedPython is installed, else as plain Python (CI installs only requirements-test.txt).

Bodies are the documented RSC GraphQL response shapes for the queries in the Rubrik definition (schema:
rubrikinc/rubrik-developer-center docs/Rubrik-Security-Cloud-API/schemas/20260914.graphql), synthetic values.
Each check has a passing body, a flip that must fail, and the fail-closed battery: empty, None, "{}", a GraphQL
error, a partial error on its own field, and the IS error envelopes (connection error, 403). The shapes were
confirmed against live responses from two RSC tenants on 2026-09-25 (not committed: customer data).
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
    import RestrictedPython  # noqa: F401  (prod runtime; optional here)
    spec = importlib.util.spec_from_file_location("restricted_sandbox_rubrik", ROOT / "tools" / "restricted_sandbox.py")
    sandbox = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sandbox)
    load_code = sandbox.load
except ImportError:
    def load_code(code, filename):
        ns = {"__name__": "rubrik_" + filename}
        exec(compile(code, filename, "exec"), ns)
        return ns

RECENT = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
OLD = (datetime.now(timezone.utc) - timedelta(days=400)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
DONE = {"hasNextPage": False, "endCursor": "Y3Vyc29yOmludDox"}


def run(key, body):
    ns = load_code((HERE / (key.lower() + ".py")).read_text(), key)
    return ns["transform"](body)


def value(key, body):
    return run(key, body)["transformedResponse"][key]


def flip(base, fn):
    b = copy.deepcopy(base)
    fn(b["data"])
    return b


def counts(**kw):
    return {"data": {k: {"count": v} for k, v in kw.items()}}


SNAP = counts(activeObjects=120, protectedObjects=100, inCompliance=95, outOfCompliance=5, noSla=10, doNotProtect=10)

ACT = {"data": {
    "backupSucceeded": {"count": 90}, "backupPartial": {"count": 5}, "backupFailed": {"count": 5},
    "recoverySucceeded": {"count": 2},
    "recentBackups": {"count": 100, "nodes": [{"activitySeriesId": "a1", "lastActivityType": "Backup", "lastActivityStatus": "Success",
                                               "startTime": RECENT, "lastUpdated": RECENT, "objectType": "VmwareVm", "clusterName": "c1"}]},
}}

RANSOM = {"data": {
    "ransomwareInvestigationEnablement": {"awsAccounts": [], "azureSubscriptions": [], "gcpProjects": [],
                                          "microsoft365Subscriptions": [{"enabled": True}], "rubrikCloudVaultLocations": [],
                                          "cloudDirectClusters": []},
    "anomalyAnalyses": {"count": 4},
}}


def sla(name, mode, protected, duration, unit):
    return {"id": name, "name": name, "isArchived": False, "isRetentionLockedSla": mode != "NO_MODE", "retentionLockMode": mode,
            "protectedObjectCount": protected, "baseFrequency": {"duration": duration, "unit": unit},
            "snapshotSchedule": {"minute": None, "hourly": None,
                                 "daily": {"basicSchedule": {"frequency": 1, "retention": 30, "retentionUnit": "DAYS"}}}}


SLA = {"data": {"slaDomains": {"count": 3, "pageInfo": DONE, "nodes": [
    sla("Gold", "COMPLIANCE", 10, 4, "HOURS"), sla("Daily", "COMPLIANCE", 5, 1, "DAYS"), sla("Unused", "NO_MODE", 0, 1, "WEEKS")]}}}

TGT = {"data": {"targets": {"count": 2, "pageInfo": DONE, "nodes": [
    {"id": "t1", "name": "vault", "targetType": "RCV_AWS", "isActive": True, "isArchived": False, "status": "READ_WRITE",
     "locationScope": "GLOBAL", "encryptionType": "KMS_MASTER_KEY_BASED"},
    {"id": "t2", "name": "s3", "targetType": "AWS", "isActive": True, "isArchived": False, "status": "READ_WRITE",
     "locationScope": "GLOBAL", "encryptionType": "RSA_KEY_BASED", "awsImmutability": {"isObjectLockEnabled": True, "lockDurationDays": 30}},
]}}}


def cluster(name, encrypted=True, kmip=1, rotated=RECENT):
    return {"uuid": name, "name": name, "isConnected": True, "isEncrypted": encrypted, "encryptionType": "SOFTWARE",
            "cipher": "AES-256" if encrypted else "", "totalKmipServers": kmip,
            "latestRotationCompletedInfo": {"completedAt": rotated, "protectionType": "KMIP", "state": "CDM_DONE"} if rotated else None}


ENC = {"data": {"clusterEncryptionInfo": {"count": 2, "pageInfo": DONE, "nodes": [cluster("c1"), cluster("c2")]}}}

TPR = {"data": {
    "tprConfiguration": {"isTprEnabled": True, "staticQuorumRequirement": 1},
    "customTprPolicies": {"count": 1, "pageInfo": DONE, "nodes": [
        {"policyId": "p1", "policyName": "Protect deletes", "quorumRequirement": 2, "actions": ["DELETE_SNAPSHOT", "EDIT_SLA"],
         "numberOfObjectTypes": 1, "numberOfProtectableObjects": 12}]},
}}


def user(uid, ops, status="ACTIVE"):
    return {"id": uid, "status": status, "roles": [{"id": "r-" + uid, "name": "role", "isOrgAdmin": False,
                                                    "effectiveRbacPermissions": [{"operations": ops}]}]}


USERS = {"data": {"usersInCurrentAndDescendantOrganization": {"count": 4, "pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": [
    user("u1", ["APPROVE_TPR_REQUEST"]), user("u2", ["APPROVE_TPR_REQUEST", "VIEW_TPR_REQUEST"]), user("u3", ["VIEW_TPR_REQUEST"]),
    user("u4", ["APPROVE_TPR_REQUEST"], status="DEACTIVATED")]}}}

ROLES = {"data": {"getAllRolesInOrgConnection": {"count": 2, "pageInfo": DONE, "nodes": [
    {"id": "r1", "name": "Administrator", "isOrgAdmin": False, "isReadOnly": True,
     "effectiveRbacPermissions": [{"operations": ["MANAGE_USER", "MANAGE_ROLE", "RESTORE_TO_ORIGIN"]}]},
    {"id": "r2", "name": "Restore Operator", "isOrgAdmin": False, "isReadOnly": False,
     "effectiveRbacPermissions": [{"operations": ["RESTORE_TO_ORIGIN", "EXPORT_SNAPSHOTS"]}]}]}}}

MFA = {"data": {"globalMfaSetting": {"isTotpEnforcedGlobal": False, "isTotpMandatory": True},
                "orgs": {"count": 2, "pageInfo": DONE, "nodes": [{"id": "o1", "name": "tenant-a"}, {"id": "o2", "name": "tenant-b"}]}}}

AUTH = counts(allUsers=10, ssoUsers=10, localUsers=0)

HOOKS = {"data": {"allWebhooksV2": [{"id": 1, "name": "siem", "status": "ENABLED", "providerType": "CUSTOM", "subscriptionType": {
    "auditSubscription": {"isSubscribedToAllAudits": True, "auditTypes": [], "severities": ["CRITICAL"]},
    "eventSubscription": {"isSubscribedToAllEvents": False, "eventTypes": ["BACKUP"], "severities": ["SEVERITY_CRITICAL"]}}}]}}


def set_count(alias, n):
    def f(d):
        d[alias]["count"] = n
    return f


# key, passing body, expected passing value, flipped body, expected flipped value, the field whose own GraphQL error must fail it
CASES = [
    ("backupSlaComplianceRatePercentage", SNAP, 95.0, flip(SNAP, set_count("outOfCompliance", 95)), 50.0, "inCompliance"),
    ("staleProtectionJobsCount", SNAP, 5, flip(SNAP, set_count("outOfCompliance", 40)), 40, "outOfCompliance"),
    ("unprotectedResourcesCount", SNAP, 20, flip(SNAP, set_count("noSla", 0)), 10, "noSla"),
    ("complianceStatus", SNAP, True, flip(SNAP, set_count("outOfCompliance", 95)), False, "inCompliance"),
    ("confirmedLicensePurchased", SNAP, True, flip(SNAP, set_count("protectedObjects", 0)), False, "protectedObjects"),
    ("isBackupEnabled", SNAP, True, flip(SNAP, set_count("protectedObjects", 0)), False, "protectedObjects"),
    ("isBackupEnabledForCriticalSystems", SNAP, True, flip(SNAP, set_count("noSla", 90)), False, "noSla"),
    ("backupSuccessRatePercentage", ACT, 90.0, flip(ACT, set_count("backupFailed", 55)), 60.0, "backupFailed"),
    ("failedBackupJobsCount", ACT, 5, flip(ACT, set_count("backupFailed", 0)), 0, "backupFailed"),
    ("isJobExecutionLogAccessible", ACT, True, flip(ACT, lambda d: d["recentBackups"].update(count=0, nodes=[])), False, "recentBackups"),
    ("isBackupLoggingEnabled", ACT, True, flip(ACT, lambda d: d["recentBackups"].update(count=0, nodes=[])), False, "recentBackups"),
    ("areBackupsTested", ACT, True, flip(ACT, set_count("recoverySucceeded", 0)), False, "recoverySucceeded"),
    ("isBackupTested", ACT, True, flip(ACT, set_count("recoverySucceeded", 0)), False, "recoverySucceeded"),
    ("isRansomwareDetectionEnabled", RANSOM, True,
     flip(RANSOM, lambda d: (d["anomalyAnalyses"].update(count=0), d["ransomwareInvestigationEnablement"]["microsoft365Subscriptions"][0].update(enabled=False))),
     False, "anomalyAnalyses"),
    ("isProtectionPolicyRPOWithinSLA", SLA, True, flip(SLA, lambda d: d["slaDomains"]["nodes"][1]["baseFrequency"].update(duration=2)), False, "slaDomains"),
    ("isDataLockComplianceModeEnabled", SLA, True, flip(SLA, lambda d: d["slaDomains"]["nodes"][1].update(retentionLockMode="GOVERNANCE")), False, "slaDomains"),
    ("isBackupImmutable", SLA, True,
     flip(SLA, lambda d: d["slaDomains"]["nodes"][1].update(retentionLockMode="NO_MODE", isRetentionLockedSla=False)), False, "slaDomains"),
    ("isBackupTypesScheduled", SLA, True,
     flip(SLA, lambda d: d["slaDomains"]["nodes"][1].update(baseFrequency=None, snapshotSchedule=None)), False, "slaDomains"),
    ("isAirGappedStorageEnabled", TGT, True, flip(TGT, lambda d: d["targets"]["nodes"][0].update(targetType="S3_COMPATIBLE")), False, "targets"),
    ("isCloudTierEncryptionEnabled", TGT, True,
     flip(TGT, lambda d: d["targets"]["nodes"][1].update(encryptionType="UNKNOWN_ENCRYPTION_TYPE")), False, "targets"),
    ("isExternalTargetEncryptionAES256", TGT, True,
     flip(TGT, lambda d: d["targets"]["nodes"][1].update(encryptionType="UNKNOWN_ENCRYPTION_TYPE")), False, "targets"),
    ("clientAESEncryptionCoveragePercentage", ENC, 100.0,
     flip(ENC, lambda d: d["clusterEncryptionInfo"]["nodes"][1].update(isEncrypted=False, cipher="")), 50.0, "clusterEncryptionInfo"),
    ("isBackupEncrypted", ENC, True, flip(ENC, lambda d: d["clusterEncryptionInfo"]["nodes"][1].update(isEncrypted=False)), False, "clusterEncryptionInfo"),
    ("isBYOKCustomerManagedKeyConfigured", ENC, True,
     flip(ENC, lambda d: d["clusterEncryptionInfo"]["nodes"][1].update(totalKmipServers=0)), False, "clusterEncryptionInfo"),
    ("isKMSKeyRotationEnabled", ENC, True,
     flip(ENC, lambda d: d["clusterEncryptionInfo"]["nodes"][1]["latestRotationCompletedInfo"].update(completedAt=OLD)), False, "clusterEncryptionInfo"),
    ("isObjectLevelQuorumPolicyConfigured", TPR, True,
     flip(TPR, lambda d: d["customTprPolicies"]["nodes"][0].update(numberOfProtectableObjects=0)), False, "tprConfiguration"),
    ("isQuorumApprovalRequiredForDeletion", TPR, True,
     flip(TPR, lambda d: d["customTprPolicies"]["nodes"][0].update(actions=["EDIT_SLA"])), False, "customTprPolicies"),
    ("quorumReviewerRoleAssignedCount", USERS, 2,
     flip(USERS, lambda d: d["usersInCurrentAndDescendantOrganization"]["nodes"][1]["roles"][0].update(
         effectiveRbacPermissions=[{"operations": ["VIEW_TPR_REQUEST"]}])), 1, "usersInCurrentAndDescendantOrganization"),
    ("isRestoreJobPermissionIsolationEnabled", ROLES, True,
     flip(ROLES, lambda d: d["getAllRolesInOrgConnection"]["nodes"][1]["effectiveRbacPermissions"][0]["operations"].append("MANAGE_ROLE")),
     False, "getAllRolesInOrgConnection"),
    ("isMFAEnforcedForUsers", MFA, True, flip(MFA, lambda d: d["globalMfaSetting"].update(isTotpMandatory=False)), False, "globalMfaSetting"),
    ("isMultiTenantRBACEnforced", MFA, True, flip(MFA, lambda d: d["orgs"].update(count=0, nodes=[])), False, "orgs"),
    ("isSSOEnabled", AUTH, True, flip(AUTH, set_count("ssoUsers", 0)), False, "ssoUsers"),
    ("isSAMLEnforced", AUTH, True, flip(AUTH, set_count("localUsers", 2)), False, "localUsers"),
    ("isAuditLogForwardingEnabled", HOOKS, True, flip(HOOKS, lambda d: d["allWebhooksV2"][0].update(status="DISABLED")), False, "allWebhooksV2"),
    ("isPolicyFailureNotificationConfigured", HOOKS, True,
     flip(HOOKS, lambda d: d["allWebhooksV2"][0]["subscriptionType"]["eventSubscription"].update(eventTypes=["ARCHIVE"])), False, "allWebhooksV2"),
]
NUMERIC = {"backupSlaComplianceRatePercentage", "staleProtectionJobsCount", "unprotectedResourcesCount", "backupSuccessRatePercentage",
           "failedBackupJobsCount", "clientAESEncryptionCoveragePercentage", "quorumReviewerRoleAssignedCount"}
IDS = [c[0] for c in CASES]


def unknown(key):
    return None if key in NUMERIC else False


def test_every_rubrik_file_is_covered():
    files = {p.stem for p in HERE.glob("*.py") if not p.stem.startswith("test_")}
    assert files == {k.lower() for k in IDS}


@pytest.mark.parametrize("key,good,good_value,bad,bad_value,field", CASES, ids=IDS)
def test_pass_and_flip(key, good, good_value, bad, bad_value, field):
    assert value(key, good) == good_value
    assert value(key, bad) == bad_value


@pytest.mark.parametrize("key,good,good_value,bad,bad_value,field", CASES, ids=IDS)
def test_wrappers_do_not_change_the_answer(key, good, good_value, bad, bad_value, field):
    for wrapped in ({"result": good}, {"apiResponse": good}, {"result": {"apiResponse": good}},
                    {"data": good, "validation": {"status": "valid", "errors": [], "warnings": []}}, json.dumps(good)):
        assert value(key, wrapped) == good_value


ERROR_ENVELOPES = [
    {},
    None,
    "{}",
    {"data": None, "errors": [{"message": "Objects are not authorized.", "path": None, "extensions": {"code": 403}}]},
    {"errors": [{"message": "An unexpected internal error occurred.", "extensions": {"code": 500}}]},
    {"integrationName": "Rubrik", "error": True, "errorType": "connection_error", "statusCode": 503, "status": "Error",
     "message": "('Connection aborted.', RemoteDisconnected('Remote end closed connection without response'))"},
    {"error": True, "errorType": "vendor_error", "statusCode": 403, "status": "Error", "message": "Forbidden"},
    {"result": {"error": True, "statusCode": 401, "status": "Error", "message": "401 Unauthorized"}},
]


@pytest.mark.parametrize("key,good,good_value,bad,bad_value,field", CASES, ids=IDS)
def test_fails_closed_on_no_evidence(key, good, good_value, bad, bad_value, field):
    for body in ERROR_ENVELOPES:
        out = run(key, body)
        assert out["transformedResponse"][key] == unknown(key), body
        assert out["additionalInfo"]["evaluation"]["failReasons"], body


@pytest.mark.parametrize("key,good,good_value,bad,bad_value,field", CASES, ids=IDS)
def test_graphql_error_on_own_field_fails_but_other_field_does_not(key, good, good_value, bad, bad_value, field):
    own = copy.deepcopy(good)
    own["errors"] = [{"message": "Missing permission", "path": [field], "extensions": {"code": 403}}]
    assert value(key, own) == unknown(key)
    other = copy.deepcopy(good)
    other["errors"] = [{"message": "Missing permission", "path": ["someOtherField"], "extensions": {"code": 403}}]
    assert value(key, other) == good_value


@pytest.mark.parametrize("key,good,good_value,bad,bad_value,field", CASES, ids=IDS)
def test_missing_field_fails_closed(key, good, good_value, bad, bad_value, field):
    b = copy.deepcopy(good)
    b["data"][field] = None
    assert value(key, b) == unknown(key)


@pytest.mark.parametrize("key,conn,body", [
    ("isProtectionPolicyRPOWithinSLA", "slaDomains", SLA),
    ("isAirGappedStorageEnabled", "targets", TGT),
    ("isBackupEncrypted", "clusterEncryptionInfo", ENC),
    ("isQuorumApprovalRequiredForDeletion", "customTprPolicies", TPR),
    ("isRestoreJobPermissionIsolationEnabled", "getAllRolesInOrgConnection", ROLES),
])
def test_unread_next_page_fails_closed(key, conn, body):
    b = copy.deepcopy(body)
    b["data"][conn]["pageInfo"] = {"hasNextPage": True, "endCursor": "Y3Vyc29yOmludDoy"}
    assert value(key, b) is False


def test_truncated_user_pagination_is_not_a_count():
    b = copy.deepcopy(USERS)
    b["data"]["usersInCurrentAndDescendantOrganization"]["pageInfo"] = {"hasNextPage": True, "endCursor": None, "truncated": True}
    assert value("quorumReviewerRoleAssignedCount", b) is None


def test_merged_pagination_counts_as_complete():
    b = copy.deepcopy(USERS)
    b["data"]["usersInCurrentAndDescendantOrganization"]["pageInfo"] = {"hasNextPage": True, "endCursor": None}
    assert value("quorumReviewerRoleAssignedCount", b) == 2


def test_rcs_vault_without_encryption_field_is_not_evidence_of_encryption():
    b = flip(TGT, lambda d: d["targets"]["nodes"].__setitem__(0, {"id": "t3", "name": "rcv-azure", "targetType": "RCS_AZURE",
                                                                   "isActive": True, "isArchived": False, "immutabilityPeriodDays": 0}))
    assert value("isAirGappedStorageEnabled", b) is True
    assert value("isCloudTierEncryptionEnabled", b) is False


def test_tpr_disabled_fails_both_quorum_checks():
    b = flip(TPR, lambda d: d["tprConfiguration"].update(isTprEnabled=False))
    assert value("isObjectLevelQuorumPolicyConfigured", b) is False
    assert value("isQuorumApprovalRequiredForDeletion", b) is False


def test_no_backups_finished_is_not_a_rate():
    b = flip(ACT, lambda d: [d[a].update(count=0) for a in ("backupSucceeded", "backupPartial", "backupFailed")])
    assert value("backupSuccessRatePercentage", b) is None


def test_unused_sla_domains_are_ignored_but_none_in_use_fails():
    b = flip(SLA, lambda d: [n.update(protectedObjectCount=0) for n in d["slaDomains"]["nodes"]])
    assert value("isProtectionPolicyRPOWithinSLA", b) is False
    assert value("isBackupTypesScheduled", b) is False


def test_no_webhooks_is_a_finding_not_an_error():
    out = run("isAuditLogForwardingEnabled", {"data": {"allWebhooksV2": []}})
    assert out["transformedResponse"]["isAuditLogForwardingEnabled"] is False
    assert "No enabled webhook" in out["additionalInfo"]["evaluation"]["failReasons"][0]
