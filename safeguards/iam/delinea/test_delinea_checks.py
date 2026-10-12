"""Delinea Platform + Secret Server checks, on bodies shaped as Delinea documents them.

No customer body has been seen: no customer has connected this integration. Shapes follow the
Delinea Platform OpenAPI specs (identity-federation.externalapi.json, vaultbroker.publicapi.json)
and the Secret Server REST API reference 12.1.2. Each check has a passing body, a measured flip
that must read False, and the unmeasured inputs (empty, None, "{}", "", an Integration-Service
error envelope, a Delinea error body, an HTML page, an unread or partial read) that must read None
and say so under additionalInfo.dataCollection, never False: a read that proves nothing is not a
failed control."""
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


def not_evaluated(out, key):
    """True when the criterion is None and the response says it was not evaluated."""
    inner = out.get("transformedResponse", out)
    collection = out["additionalInfo"]["dataCollection"]
    return (inner[key] is None and collection["status"] == "error"
            and len(collection["errors"]) > 0 and all(isinstance(e, str) and e for e in collection["errors"]))


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
    assert t({"records": [], "count": 0, "totalCount": 3})["isSSOEnabled"] is None      # partial read, none enabled
    assert t(dict(off, totalCount=2))["isSSOEnabled"] is None
    # an empty list is measured only against an explicit completed count of 0
    assert t({"records": []})["isSSOEnabled"] is None
    assert t({"records": [], "count": 0})["isSSOEnabled"] is None
    assert not_evaluated(t({"records": []}), "isSSOEnabled")
    for odd in ["0", True, -1, 1.5, [], {}]:
        assert t({"records": [], "totalCount": odd})["isSSOEnabled"] is None
        assert t(dict(off, totalCount=odd))["isSSOEnabled"] is None                    # not a count: completeness unknown
    assert t(dict(off, totalCount=1))["isSSOEnabled"] is False
    assert t({k: v for k, v in off.items() if k != "totalCount"})["isSSOEnabled"] is False
    assert t(dict(good, totalCount=2))["isSSOEnabled"] is True                          # an enabled provider was read
    assert t({"records": "x"})["isSSOEnabled"] is None
    for bad in EMPTYISH:
        assert t(bad)["isSSOEnabled"] is None
        assert not_evaluated(t(bad), "isSSOEnabled")
    assert "additionalInfo" not in t(good)
    assert "additionalInfo" not in t(off)


def test_pam():
    t = load("ispamenabled")
    vault = {"vaultId": "v1", "name": "SS", "type": "SecretServer", "isDefault": True, "isActive": True,
             "connection": {"url": "https://tenant.secretservercloud.com", "oAuthProfileId": "p"}}
    assert t({"vaults": [vault]})["isPAMEnabled"] is True
    assert t({"vaults": [dict(vault, isActive=False)]})["isPAMEnabled"] is False
    assert t({"vaults": [dict(vault, connection={"url": ""})]})["isPAMEnabled"] is False
    assert t({"vaults": [dict(vault, connection=None)]})["isPAMEnabled"] is False
    assert t({"vaults": [dict(vault, isActive=False), dict(vault, connection={})]})["isPAMEnabled"] is False
    # the vaults body carries no count, so an empty list cannot show a completed read of zero vaults
    assert t({"vaults": []})["isPAMEnabled"] is None
    assert not_evaluated(t({"vaults": []}), "isPAMEnabled")
    assert t({"vaults": "x"})["isPAMEnabled"] is None
    for bad in EMPTYISH:
        assert t(bad)["isPAMEnabled"] is None
        assert not_evaluated(t(bad), "isPAMEnabled")
    assert "additionalInfo" not in t({"vaults": [dict(vault, isActive=False)]})


def test_pim():
    t = load("isprivilegedidentitymanagementenabled")
    good = {"statuses": [{"heartbeatStatus": "Success", "total": 40}, {"heartbeatStatus": "Disabled", "total": 10}]}
    assert t(good)["isPrivilegedIdentityManagementEnabled"] is True
    passive = {"statuses": [{"heartbeatStatus": "Disabled", "total": 50}, {"heartbeatStatus": "Failed", "total": 2}]}
    assert t(passive)["isPrivilegedIdentityManagementEnabled"] is False
    key = "isPrivilegedIdentityManagementEnabled"
    zero_success = {"statuses": [{"heartbeatStatus": "Success", "total": 0}, {"heartbeatStatus": "Disabled", "total": 3}]}
    assert t(zero_success)[key] is False                                                # counts exist, none Success
    assert "additionalInfo" not in t(passive)
    # no secrets counted at all cannot be told apart from a service user who sees none
    assert t({"statuses": []})[key] is None
    assert not_evaluated(t({"statuses": []}), key)
    assert t({"statuses": [{"heartbeatStatus": "Success", "total": 0}, {"heartbeatStatus": "Disabled", "total": 0}]})[key] is None
    assert t({"statuses": ["x", None]})[key] is None
    assert t({"statuses": "x"})[key] is None
    assert t({"statuses": [{"heartbeatStatus": "Success", "total": "40"}]})[key] is None
    assert not_evaluated(t({"statuses": [{"heartbeatStatus": "Success", "total": "40"}]}), key)
    assert t({"statuses": [{"heartbeatStatus": "Success", "total": True}]})[key] is None
    # a negative or non-integer total is not a count: never True, never False
    for odd in [-1, -50, 1.5, None, [], {}]:
        body = {"statuses": [{"heartbeatStatus": "Success", "total": odd}, {"heartbeatStatus": "Disabled", "total": 3}]}
        assert t(body)[key] is None
        assert not_evaluated(t(body), key)
    assert t({"statuses": [{"heartbeatStatus": "Disabled", "total": -5}]})[key] is None
    assert t({"statuses": [{"heartbeatStatus": "Success", "total": 40}, {"heartbeatStatus": "Disabled", "total": -1}]})[key] is None
    for bad in EMPTYISH:
        assert t(bad)[key] is None
        assert not_evaluated(t(bad), key)


def test_workflow():
    t = load("isworkflowautomationenabled")
    tpl = {"workflowTemplateId": 1, "name": "Approval", "active": True, "workflowType": "AccessRequest"}
    assert t(paging([tpl]))["isWorkflowAutomationEnabled"] is True
    assert t(paging([dict(tpl, active=False)]))["isWorkflowAutomationEnabled"] is False
    assert t(paging([dict(tpl, workflowType="SecretEraseRequest")]))["isWorkflowAutomationEnabled"] is False
    assert t(paging([]))["isWorkflowAutomationEnabled"] is False                        # complete, none active
    assert t(paging([], has_next=True))["isWorkflowAutomationEnabled"] is None         # more pages were not read
    assert t(paging([dict(tpl, active=False)], has_next=True))["isWorkflowAutomationEnabled"] is None
    assert not_evaluated(t(paging([], has_next=True)), "isWorkflowAutomationEnabled")
    assert t(paging([tpl], has_next=True))["isWorkflowAutomationEnabled"] is True      # an active one was read
    assert t({"records": "x"})["isWorkflowAutomationEnabled"] is None
    inactive = dict(tpl, active=False)
    # more templates than were read, with no next page flag: not a complete read
    assert t({"records": [inactive], "total": 5, "hasNext": False})["isWorkflowAutomationEnabled"] is None
    assert t({"records": [inactive], "total": 1, "hasNext": False})["isWorkflowAutomationEnabled"] is False
    assert t({"records": [inactive], "hasNext": False})["isWorkflowAutomationEnabled"] is False
    for odd in ["1", True, -1, 1.5]:
        assert t({"records": [inactive], "total": odd, "hasNext": False})["isWorkflowAutomationEnabled"] is None
    # an empty list is measured only against an explicit completed count of 0
    assert t({"records": [], "hasNext": False})["isWorkflowAutomationEnabled"] is None
    assert t({"records": []})["isWorkflowAutomationEnabled"] is None
    assert t({"records": [], "total": "0", "hasNext": False})["isWorkflowAutomationEnabled"] is None
    assert t({"records": [], "total": 0, "hasNext": False})["isWorkflowAutomationEnabled"] is False
    for bad in EMPTYISH:
        assert t(bad)["isWorkflowAutomationEnabled"] is None
        assert not_evaluated(t(bad), "isWorkflowAutomationEnabled")
    assert "additionalInfo" not in t(paging([dict(tpl, active=False)]))


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
    assert "additionalInfo" not in t(sod([policy(1, approve=False)]))
    key = "isSeparationOfDutiesEnabled"
    assert t(sod([policy(1)], has_next=True))[key] is None                              # more policies than were read
    assert not_evaluated(t(sod([policy(1)], has_next=True)), key)
    short = sod([policy(1), policy(2)])
    short["policyDetails"] = short["policyDetails"][:1]
    assert t(short)[key] is None                                                        # detail count mismatch
    assert not_evaluated(t(short), key)
    denied = sod([policy(1), policy(2)])
    denied["policyDetails"][1] = ERR_SS
    assert t(denied)[key] is None                                                       # a policy could not be read
    assert not_evaluated(t(denied), key)
    unread = sod([policy(1), policy(2)])
    unread["policyDetails"][1] = None
    assert t(unread)[key] is None
    assert t(sod([]))[key] is False                                                     # all read, none qualifies
    assert t(paging([{"secretPolicyId": 1}]))[key] is None                              # fan-out never ran
    assert not_evaluated(t(paging([{"secretPolicyId": 1}])), key)
    assert t({"policyDetails": []})[key] is None
    # more policies than were read, with no next page flag
    more = sod([policy(1, approve=False)])
    more["total"] = 4
    assert t(more)[key] is None
    assert not_evaluated(t(more), key)
    for odd in ["1", True, -1, 1.5]:
        bad_total = sod([policy(1, approve=False)])
        bad_total["total"] = odd
        assert t(bad_total)[key] is None
    # an empty list is measured only against an explicit completed count of 0
    assert t({"records": [], "policyDetails": []})[key] is None
    assert t({"records": [], "policyDetails": [], "total": "0", "hasNext": False})[key] is None
    assert t({"records": [], "policyDetails": [], "total": 0, "hasNext": False})[key] is False
    assert t({"records": "x", "policyDetails": []})[key] is None
    for bad in EMPTYISH:
        assert t(bad)[key] is None
        assert not_evaluated(t(bad), key)
