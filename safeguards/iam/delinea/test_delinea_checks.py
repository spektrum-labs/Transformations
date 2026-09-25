"""Delinea Platform + Secret Server checks, on bodies shaped as Delinea documents them.

No customer body has been seen: no customer has connected this integration. Shapes follow the
Delinea Platform OpenAPI specs (identity-federation.externalapi.json, vaultbroker.publicapi.json)
and the Secret Server REST API reference 12.1.2. Each check has a passing body, a flip that must
fail, and the fail-closed inputs (empty, None, "{}", "", an Integration-Service error envelope,
a Delinea error body and an HTML page)."""
import copy
import importlib.util
import pathlib

HERE = pathlib.Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location("delinea_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


ERR_IS = {"error": True, "statusCode": 401, "message": "Unauthorized"}
ERR_SS = {"message": "Access Denied", "errorCode": "API_AccessDenied"}
ERR_PLAT = {"type": "https://tools.ietf.org/html/rfc7231#section-6.5.3", "title": "Forbidden", "status": 403}
EMPTYISH = [{}, None, "{}", "", ERR_IS, ERR_SS, ERR_PLAT, "<html><body>Sign in</body></html>", {"success": False, "message": "x"}]


def paging(records, has_next=False):
    return {"records": records, "total": len(records), "skip": 0, "take": 100, "hasNext": has_next, "success": True}


def test_sso():
    t = load("isssoenabled")
    good = {"records": [{"id": "a", "entityId": "https://sts.example.com", "enabled": True}], "count": 1, "totalCount": 1}
    assert t(good)["isSSOEnabled"] is True
    assert t({"apiResponse": good})["isSSOEnabled"] is True
    off = copy.deepcopy(good)
    off["records"][0]["enabled"] = False
    assert t(off)["isSSOEnabled"] is False
    assert t({"records": [], "count": 0, "totalCount": 0})["isSSOEnabled"] is False
    assert t({"records": [], "count": 0, "totalCount": 3})["isSSOEnabled"] is False
    for bad in EMPTYISH:
        assert t(bad)["isSSOEnabled"] is False


def test_pam():
    t = load("ispamenabled")
    vault = {"vaultId": "v1", "name": "SS", "type": "SecretServer", "isDefault": True, "isActive": True,
             "connection": {"url": "https://tenant.secretservercloud.com", "oAuthProfileId": "p"}}
    assert t({"vaults": [vault]})["isPAMEnabled"] is True
    assert t({"vaults": [dict(vault, isActive=False)]})["isPAMEnabled"] is False
    assert t({"vaults": [dict(vault, connection={"url": ""})]})["isPAMEnabled"] is False
    assert t({"vaults": []})["isPAMEnabled"] is False
    for bad in EMPTYISH:
        assert t(bad)["isPAMEnabled"] is False


def test_pim():
    t = load("isprivilegedidentitymanagementenabled")
    good = {"statuses": [{"heartbeatStatus": "Success", "total": 40}, {"heartbeatStatus": "Disabled", "total": 10}]}
    assert t(good)["isPrivilegedIdentityManagementEnabled"] is True
    passive = {"statuses": [{"heartbeatStatus": "Disabled", "total": 50}, {"heartbeatStatus": "Failed", "total": 2}]}
    assert t(passive)["isPrivilegedIdentityManagementEnabled"] is False
    assert t({"statuses": []})["isPrivilegedIdentityManagementEnabled"] is False
    assert t({"statuses": [{"heartbeatStatus": "Success", "total": "40"}]})["isPrivilegedIdentityManagementEnabled"] is False
    for bad in EMPTYISH:
        assert t(bad)["isPrivilegedIdentityManagementEnabled"] is False


def test_workflow():
    t = load("isworkflowautomationenabled")
    tpl = {"workflowTemplateId": 1, "name": "Approval", "active": True, "workflowType": "AccessRequest"}
    assert t(paging([tpl]))["isWorkflowAutomationEnabled"] is True
    assert t(paging([dict(tpl, active=False)]))["isWorkflowAutomationEnabled"] is False
    assert t(paging([dict(tpl, workflowType="SecretEraseRequest")]))["isWorkflowAutomationEnabled"] is False
    assert t(paging([], has_next=True))["isWorkflowAutomationEnabled"] is False
    for bad in EMPTYISH:
        assert t(bad)["isWorkflowAutomationEnabled"] is False


def test_orphan_accounts():
    t = load("openorphanaccountscount")
    good = {"isDiscoveryEnabled": True, "discoverySourceCount": 2, "discoveryFetchEndDateTime": "2026-09-24T02:00:00Z",
            "itemMetrics": [{"itemType": "account", "managedCount": 120, "notManagedCount": 7},
                            {"itemType": "service-account", "managedCount": 10, "notManagedCount": 2},
                            {"itemType": "computer", "managedCount": 300, "notManagedCount": 40}]}
    assert t(good)["openOrphanAccountsCount"] == 9
    clean = copy.deepcopy(good)
    for m in clean["itemMetrics"]:
        m["notManagedCount"] = 0
    assert t(clean)["openOrphanAccountsCount"] == 0
    assert t(dict(good, isDiscoveryEnabled=False))["openOrphanAccountsCount"] is None
    assert t(dict(good, discoverySourceCount=0))["openOrphanAccountsCount"] is None
    assert t(dict(good, discoveryFetchEndDateTime=None))["openOrphanAccountsCount"] is None
    assert t(dict(good, itemMetrics=[{"itemType": "computer", "notManagedCount": 4}]))["openOrphanAccountsCount"] is None
    no_metrics = dict(good)
    del no_metrics["itemMetrics"]
    assert t(no_metrics)["openOrphanAccountsCount"] is None
    for bad in EMPTYISH:
        assert t(bad)["openOrphanAccountsCount"] is None


def policy(pid, approve=True, apply="Enforced", groups=True, secrets=5, active=True):
    return {"secretPolicyId": pid, "secretPolicyName": "P%d" % pid, "active": active, "affectedSecretCount": secrets,
            "affectedInheritingSecretsCount": 0,
            "securityItems": {"requireApprovalForAccess": {"value": approve, "policyApplyType": apply, "policyItemId": 9},
                              "approvalGroups": {"value": [{"groupId": 3, "userGroupMapType": "Group"}] if groups else [],
                                                 "policyApplyType": apply},
                              "approvalWorkflow": {"value": None, "policyApplyType": "NotSet"}}}


def sod(details, has_next=False):
    recs = [{"secretPolicyId": d["secretPolicyId"], "secretPolicyName": d["secretPolicyName"], "active": True}
            for d in details if isinstance(d, dict) and "secretPolicyId" in d]
    body = paging(recs, has_next)
    body["policyDetails"] = details
    return body


def test_separation_of_duties():
    t = load("isseparationofdutiesenabled")
    assert t(sod([policy(1, approve=False), policy(2)]))["isSeparationOfDutiesEnabled"] is True
    assert t(sod([policy(1, approve=False)]))["isSeparationOfDutiesEnabled"] is False
    assert t(sod([policy(1, apply="NotSet")]))["isSeparationOfDutiesEnabled"] is False
    assert t(sod([policy(1, groups=False)]))["isSeparationOfDutiesEnabled"] is False
    assert t(sod([policy(1, secrets=0)]))["isSeparationOfDutiesEnabled"] is False
    assert t(sod([policy(1, active=False)]))["isSeparationOfDutiesEnabled"] is False
    assert t(sod([policy(1)], has_next=True))["isSeparationOfDutiesEnabled"] is False
    short = sod([policy(1), policy(2)])
    short["policyDetails"] = short["policyDetails"][:1]
    assert t(short)["isSeparationOfDutiesEnabled"] is False
    denied = sod([policy(1), policy(2)])
    denied["policyDetails"][1] = ERR_SS
    assert t(denied)["isSeparationOfDutiesEnabled"] is False
    assert t(sod([]))["isSeparationOfDutiesEnabled"] is False
    assert t(paging([{"secretPolicyId": 1}]))["isSeparationOfDutiesEnabled"] is False     # fan-out never ran
    for bad in EMPTYISH:
        assert t(bad)["isSeparationOfDutiesEnabled"] is False
