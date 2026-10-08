"""JumpCloud service-account checks (listServiceAccounts, GET /api/v2/service-accounts).

isNonHumanIdentityInventoryEnabled and isAPIAccountPermissionScoped answer only from a complete
service-account list; every no-evidence or partial body is Unevaluated (None + dataCollection error).
"""
import importlib.util
from pathlib import Path

import pytest

HERE = Path(__file__).parent
KEYS = ["isNonHumanIdentityInventoryEnabled", "isAPIAccountPermissionScoped"]

NO_EVIDENCE = {
    "null": None,
    "empty_dict": {},
    "empty_string": "",
    "forbidden_403": {"message": "Forbidden"},
    "error": {"error": "invalid api key"},
    "unrelated": {"items": [{"id": 1}]},
    "no_total": {"results": [{"name": "svc", "roleName": "Read Only"}]},
    "partial": {"totalCount": 3, "results": [{"name": "a", "roleName": "Read Only"}]},
    "non_object_records": {"totalCount": 1, "results": ["svc"]},
}


def load(key):
    spec = importlib.util.spec_from_file_location("jcsa_" + key, HERE / (key + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run(key, body):
    out = load(key).transform(body)
    return out["transformedResponse"][key], out["additionalInfo"]["dataCollection"]["status"]


def sa(name, role):
    return {"name": name, "objectId": "o-" + name, "roleId": "r", "roleName": role, "status": "ACTIVE"}


@pytest.mark.parametrize("key", KEYS)
@pytest.mark.parametrize("name", sorted(NO_EVIDENCE))
def test_no_evidence_is_unevaluated(key, name):
    assert run(key, NO_EVIDENCE[name]) == (None, "error")


def test_inventory_true_when_service_accounts_exist():
    body = {"totalCount": 2, "results": [sa("ci", "Read Only"), sa("siem", "Help Desk")]}
    assert run("isNonHumanIdentityInventoryEnabled", body) == (True, "success")


def test_inventory_false_when_empty():
    assert run("isNonHumanIdentityInventoryEnabled", {"totalCount": 0, "results": []}) == (False, "success")


def test_inventory_reads_wrapped_body():
    body = {"apiResponse": {"totalCount": 1, "results": [sa("ci", "Manager")]}}
    assert run("isNonHumanIdentityInventoryEnabled", body) == (True, "success")


def test_scoped_true_when_no_full_admin_roles():
    body = {"totalCount": 3, "results": [sa("a", "Read Only"), sa("b", "Manager"), sa("c", "Custom SIEM reader")]}
    assert run("isAPIAccountPermissionScoped", body) == (True, "success")


@pytest.mark.parametrize("role", ["Administrator With Billing", "Administrator", "administrator with billing"])
def test_scoped_false_on_full_admin_role(role):
    body = {"totalCount": 2, "results": [sa("a", "Read Only"), sa("b", role)]}
    assert run("isAPIAccountPermissionScoped", body) == (False, "success")


def test_scoped_unevaluated_on_empty_inventory():
    assert run("isAPIAccountPermissionScoped", {"totalCount": 0, "results": []}) == (None, "error")


def test_scoped_unevaluated_when_a_role_is_unreadable():
    body = {"totalCount": 2, "results": [sa("a", "Read Only"), {"name": "b", "roleId": "r"}]}
    assert run("isAPIAccountPermissionScoped", body) == (None, "error")


def test_full_admin_wins_over_unreadable_role():
    body = {"totalCount": 2, "results": [sa("a", "Administrator"), {"name": "b"}]}
    assert run("isAPIAccountPermissionScoped", body) == (False, "success")
