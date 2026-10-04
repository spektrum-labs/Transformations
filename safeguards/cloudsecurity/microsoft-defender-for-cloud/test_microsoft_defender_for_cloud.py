"""Microsoft Defender for Cloud (Azure subscription posture): every transform, synthetic bodies only.

Fixture shapes follow the Microsoft Learn REST samples (no customer data; ids are all-zero GUIDs):
  secure score     https://learn.microsoft.com/en-us/rest/api/defenderforcloud/secure-scores/get
  assessments      https://learn.microsoft.com/en-us/rest/api/defenderforcloud/assessments/list
  assessment meta  https://learn.microsoft.com/en-us/rest/api/defenderforcloud/assessments-metadata/list-by-subscription
  pricings         https://learn.microsoft.com/en-us/rest/api/defenderforcloud/pricings/list
  activity log     https://learn.microsoft.com/en-us/rest/api/monitor/subscription-diagnostic-settings/list

Fail closed: a missing, error, partial (unread nextLink) or unrecognised body reads None, never True and
never 0 (isPublicStorageBucketExposed is inverted: never False).
"""
import importlib.util
import json
from pathlib import Path

import pytest

HERE = Path(__file__).parent
SUB = "/subscriptions/00000000-0000-0000-0000-000000000000"
KEYS = ["compliancePercentage", "confirmedLicensePurchased", "criticalOpenFindingsCount",
        "excessiveIAMPermissionsFindingsCount", "isIAMLoggingEnabled", "isMFAEnforcedForUsers",
        "isPublicStorageBucketExposed", "isRuntimeThreatDetectionEnabled", "unencryptedStorageResourceCount"]


def load(name):
    spec = importlib.util.spec_from_file_location("mdfc_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MODULES = {k: load(k) for k in KEYS}


def value(key, payload):
    return MODULES[key].transform(payload)["transformedResponse"][key]


def assessment(n, name, status, severity=None, resource="vm"):
    props = {"displayName": name, "status": {"code": status},
             "resourceDetails": {"source": "Azure", "id": SUB + "/resourceGroups/rg/providers/x/" + resource + str(n)}}
    if severity:
        props["metadata"] = {"displayName": name, "severity": severity}
    return {"id": SUB + "/providers/Microsoft.Security/assessments/0000000" + str(n),
            "name": "00000000-0000-0000-0000-00000000000" + str(n), "type": "Microsoft.Security/assessments",
            "properties": props}


def page(items, next_link=None):
    body = {"value": items}
    if next_link:
        body["nextLink"] = next_link
    return body


MFA_OWNER = "Accounts with owner permissions on Azure resources should be MFA enabled"
MFA_WRITE = "Accounts with write permissions on Azure resources should be MFA enabled"
STORAGE = "Storage account public access should be disallowed"
OWNERS = "A maximum of 3 owners should be designated for subscriptions"
GUEST = "Guest accounts with owner permissions on Azure resources should be removed"
TDE = "Transparent Data Encryption on SQL databases should be enabled"
VM_ENC = "Virtual machines should encrypt temp disks, caches, and data flows between Compute and Storage resources"
OTHER = "Install endpoint protection solution on virtual machine scale sets"

NO_EVIDENCE = [None, {}, "{}", "", b"", {"hello": "world"}, {"foo": {"bar": [1, 2, 3]}},
               {"error": {"code": "AuthorizationFailed", "message": "no access"}},
               {"statusCode": 401, "error": "Unauthorized"}, {"statusCode": 403, "error": "Forbidden"},
               {"value": "not-a-list"}, [{"x": 1}], "not json"]


@pytest.mark.parametrize("key", KEYS)
@pytest.mark.parametrize("body", NO_EVIDENCE, ids=lambda b: str(b)[:30])
def test_no_evidence_reads_none(key, body):
    out = MODULES[key].transform(body)
    assert out["transformedResponse"][key] is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"


@pytest.mark.parametrize("key", [k for k in KEYS if k not in ("compliancePercentage",)])
def test_unread_next_page_is_partial_not_evidence(key):
    items = [assessment(1, MFA_OWNER, "Healthy", "High"), assessment(2, STORAGE, "Healthy", "Medium"),
             assessment(3, OWNERS, "Healthy", "Low"), assessment(4, TDE, "Healthy", "Medium")]
    if key in ("confirmedLicensePurchased", "isRuntimeThreatDetectionEnabled"):
        items = [{"name": "VirtualMachines", "properties": {"pricingTier": "Standard"}}]
    if key == "isIAMLoggingEnabled":
        items = []
    body = page(items, "https://management.azure.com" + SUB + "/providers/Microsoft.Security/assessments?$skipToken=x")
    assert value(key, body) is None
    truncated = page(items)
    truncated["paginationTruncated"] = True
    assert value(key, truncated) is None


def test_permission_error_names_the_roles():
    body = {"vendorErrorAsResponse": {"status": 403, "body": {"error": {"code": "AuthorizationFailed"}}}}
    out = MODULES["isMFAEnforcedForUsers"].transform(body)
    assert out["transformedResponse"]["isMFAEnforcedForUsers"] is None
    assert out["additionalInfo"]["dataCollection"]["errorCode"] == "permission_not_granted"
    assert "Security Reader" in out["additionalInfo"]["dataCollection"]["requiredPermission"]


# secure score -----------------------------------------------------------------------------------

def score(percentage, current=23.53, maximum=39):
    return {"name": "ascScore", "type": "Microsoft.Security/secureScores",
            "properties": {"displayName": "ASC score",
                           "score": {"current": current, "max": maximum, "percentage": percentage}, "weight": 67}}


def test_secure_score_percentage():
    assert value("compliancePercentage", score(0.6033)) == 60.33
    assert value("compliancePercentage", {"apiResponse": score(1)}) == 100.0
    assert value("compliancePercentage", json.dumps(score(0))) == 0.0


@pytest.mark.parametrize("bad", [score(None), score(1.5), score(-0.1), score(True), score(0.5, maximum=0),
                                 {"properties": {}}])
def test_secure_score_unreadable_is_none(bad):
    assert value("compliancePercentage", bad) is None


# Defender plans ---------------------------------------------------------------------------------

def plans(**tiers):
    return page([{"id": SUB + "/providers/Microsoft.Security/pricings/" + n, "name": n,
                  "type": "Microsoft.Security/pricings", "properties": {"pricingTier": t}} for n, t in tiers.items()])


def test_license_any_paid_plan():
    assert value("confirmedLicensePurchased", plans(VirtualMachines="Free", StorageAccounts="Standard")) is True
    assert value("confirmedLicensePurchased", plans(VirtualMachines="Free", CloudPosture="Free")) is False
    assert value("confirmedLicensePurchased", page([])) is None
    assert value("confirmedLicensePurchased", page([{"name": "VirtualMachines", "properties": {}}])) is None


def test_runtime_threat_detection_is_defender_for_servers():
    out = MODULES["isRuntimeThreatDetectionEnabled"].transform(plans(VirtualMachines="Standard", Containers="Free"))
    assert out["transformedResponse"]["isRuntimeThreatDetectionEnabled"] is True
    assert out["transformedResponse"]["defenderPlans"] == {"VirtualMachines": "Standard", "Containers": "Free"}
    assert value("isRuntimeThreatDetectionEnabled", plans(VirtualMachines="Free", Containers="Standard")) is False
    assert value("isRuntimeThreatDetectionEnabled", plans(Containers="Standard")) is None


# activity log export ----------------------------------------------------------------------------

def setting(logs, **dest):
    props = {"logs": logs}
    props.update(dest)
    return {"id": SUB + "/providers/microsoft.insights/diagnosticSettings/ds", "name": "ds", "properties": props}


WS = {"workspaceId": SUB + "/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/w"}


def test_activity_log_export():
    both = [{"category": "Administrative", "enabled": True}, {"category": "Security", "enabled": True}]
    assert value("isIAMLoggingEnabled", page([setting(both, **WS)])) is True
    assert value("isIAMLoggingEnabled", page([setting([{"categoryGroup": "allLogs", "enabled": True}], **WS)])) is True
    assert value("isIAMLoggingEnabled", page([setting(both)])) is False
    assert value("isIAMLoggingEnabled", page([setting([{"category": "Administrative", "enabled": True},
                                                       {"category": "Security", "enabled": False}], **WS)])) is False
    assert value("isIAMLoggingEnabled", page([])) is False


# assessments ------------------------------------------------------------------------------------

def test_mfa_on_privileged_accounts():
    key = "isMFAEnforcedForUsers"
    assert value(key, page([assessment(1, MFA_OWNER, "Healthy"), assessment(2, MFA_WRITE, "Healthy")])) is True
    assert value(key, page([assessment(1, MFA_OWNER, "Healthy"), assessment(2, MFA_WRITE, "Unhealthy")])) is False
    legacy = "MFA should be enabled on accounts with owner permissions on your subscription"
    assert value(key, page([assessment(1, legacy, "Unhealthy")])) is False
    assert value(key, page([assessment(1, MFA_OWNER, "NotApplicable"), assessment(2, OTHER, "Healthy")])) is None
    assert value(key, page([])) is None


def test_public_storage_is_inverted():
    key = "isPublicStorageBucketExposed"
    assert value(key, page([assessment(1, STORAGE, "Healthy"), assessment(2, STORAGE, "Unhealthy")])) is True
    assert value(key, page([assessment(1, STORAGE, "Healthy")])) is False
    assert value(key, page([assessment(1, STORAGE, "NotApplicable")])) is None
    assert value(key, page([])) is None


def test_owner_permission_findings_count():
    key = "excessiveIAMPermissionsFindingsCount"
    assert value(key, page([assessment(1, OWNERS, "Unhealthy"), assessment(2, GUEST, "Unhealthy"),
                            assessment(3, OTHER, "Unhealthy")])) == 2
    assert value(key, page([assessment(1, OWNERS, "Healthy"), assessment(2, GUEST, "Healthy")])) == 0
    assert value(key, page([assessment(1, OTHER, "Unhealthy")])) is None


def test_unencrypted_storage_count():
    key = "unencryptedStorageResourceCount"
    assert value(key, page([assessment(1, TDE, "Unhealthy"), assessment(2, VM_ENC, "Unhealthy"),
                            assessment(3, VM_ENC, "Healthy")])) == 2
    assert value(key, page([assessment(1, TDE, "Healthy")])) == 0
    assert value(key, page([assessment(1, OTHER, "Healthy")])) is None


def test_high_severity_unhealthy_count_inline_metadata():
    key = "criticalOpenFindingsCount"
    body = page([assessment(1, MFA_OWNER, "Unhealthy", "High"), assessment(2, STORAGE, "Unhealthy", "Medium"),
                 assessment(3, OTHER, "Healthy", "High")])
    assert value(key, body) == 1
    assert value(key, page([assessment(1, OTHER, "Healthy", "High")])) == 0


def test_high_severity_joined_from_metadata_workflow():
    key = "criticalOpenFindingsCount"
    a = [assessment(1, MFA_OWNER, "Unhealthy"), assessment(2, STORAGE, "Unhealthy"), assessment(3, OTHER, "Healthy")]
    meta = page([{"name": a[0]["name"], "properties": {"displayName": MFA_OWNER, "severity": "High"}},
                 {"name": a[1]["name"], "properties": {"displayName": STORAGE, "severity": "Medium"}}])
    assert value(key, {"assessments": page(a), "assessmentMetadata": meta}) == 1
    # an Unhealthy assessment whose severity cannot be resolved makes the count incomplete
    meta_short = page([{"name": a[0]["name"], "properties": {"displayName": MFA_OWNER, "severity": "High"}}])
    assert value(key, {"assessments": page(a), "assessmentMetadata": meta_short}) is None
    assert value(key, {"assessments": page([]), "assessmentMetadata": meta}) is None
    assert value(key, {"assessmentMetadata": meta}) is None


@pytest.mark.parametrize("key", KEYS)
def test_compiles_in_the_production_sandbox(key):
    import sys
    sys.path.insert(0, str(HERE.parents[2] / "tools"))
    from restricted_sandbox import load as sandbox_load
    ns = sandbox_load((HERE / (key + ".py")).read_text(), key + ".py")
    assert ns["transform"]({})["transformedResponse"][key] is None
