"""Azure AD One-Click areAdminAccountsSeparate from role assignments + users (Graph)."""
import importlib.util
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "aad_sep", Path(__file__).with_name("areadminaccountsseparate_roleassignments.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

GA = "62e90394-69f5-4237-9190-012177145e10"
READER = "88d8e3e3-8f55-4a1e-953a-9b9898b8876b"  # Directory Readers: not privileged here
E3 = "6fd2c87f-b296-42f0-b197-1e91e994b900"
OTHER_SKU = "078d2b04-f1bd-4111-bbd4-b4b1b354cef4"  # Entra ID P1: no mailbox


def ra(pid, role=GA, ptype="#microsoft.graph.user"):
    return {"principalId": pid, "roleDefinitionId": role, "directoryScopeId": "/",
            "principal": {"@odata.type": ptype, "id": pid}}


def user(uid, mail=None, skus=()):
    return {"id": uid, "userPrincipalName": uid + "@t.example", "mail": mail, "accountEnabled": True,
            "assignedLicenses": [{"skuId": s, "disabledPlans": []} for s in skus]}


def body(assignments, users, **extra):
    b = {"roleAssignments": {"value": assignments}, "users": {"value": users}}
    b.update(extra)
    return b


def run(payload):
    out = m.transform(payload)
    return out["transformedResponse"]["areAdminAccountsSeparate"], out["additionalInfo"]["dataCollection"]["status"]


def test_dedicated_unlicensed_admins_pass():
    b = body([ra("adm1"), ra("adm2"), ra("sp1", ptype="#microsoft.graph.servicePrincipal")],
             [user("adm1", skus=[OTHER_SKU]), user("adm2"), user("alice", mail="a@t.example", skus=[E3])])
    assert run(b) == (True, "success")


def test_admin_with_exchange_licence_fails():
    b = body([ra("adm1"), ra("alice")], [user("adm1"), user("alice", skus=[E3])])
    assert run(b) == (False, "success")


def test_admin_with_mail_attribute_fails():
    b = body([ra("adm1")], [user("adm1", mail="adm1@t.example")])
    assert run(b) == (False, "success")


def test_non_privileged_role_ignored():
    b = body([ra("adm1"), ra("alice", role=READER)], [user("adm1"), user("alice", mail="a@t.example", skus=[E3])])
    assert run(b) == (True, "success")


NO_EVIDENCE = {
    "null": None,
    "empty_dict": {},
    "empty_string": "",
    "error": {"error": {"code": "Authorization_RequestDenied", "message": "Insufficient privileges"}},
    "roles_error": {"roleAssignments": {"error": {"code": "Forbidden"}}, "users": {"value": [user("a")]}},
    "users_missing": {"roleAssignments": {"value": [ra("a")]}},
    "unrelated": {"value": [{"id": 1}]},
    "users_paged": {
        "roleAssignments": {"value": [ra("a")]},
        "users": {"value": [user("a")], "@odata.nextLink": "https://graph.microsoft.com/v1.0/users?$skiptoken=x"}},
    "roles_paged": {
        "roleAssignments": {"value": [ra("a")], "@odata.nextLink": "https://graph.microsoft.com/next"},
        "users": {"value": [user("a")]}},
    "group_holder": body([ra("g1", ptype="#microsoft.graph.group")], [user("a")]),
    "admin_missing_from_users": body([ra("ghost")], [user("a")]),
    "no_licence_field": body([ra("a")], [{"id": "a", "mail": None}]),
    "no_human_admin": body([ra("sp", ptype="#microsoft.graph.servicePrincipal")], [user("a")]),
    "empty_users": body([ra("a")], []),
}


@pytest.mark.parametrize("name", sorted(NO_EVIDENCE))
def test_no_evidence_is_unevaluated(name):
    assert run(NO_EVIDENCE[name]) == (None, "error")
