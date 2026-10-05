"""JumpCloud service-account checks against the shapes Integration-Service really hands them.

The sibling test_jumpcloud_service_accounts.py drives the transforms with bare bodies. This file
wraps the same records the way production does, so a pass or fail here is a pass or fail the
customer would see:

  * success: IS returns {"result": {"apiResponse": <vendor body>}} (shape seen on the 2026-09-30
    AGI Media probe of /api/v2/roles through the same JumpCloud definition).
  * vendor error: IS returns {"result": {"errorMessage", "vendorStatus", "vendorUrl", ...}}
    (the exact envelope the 2026-09-30 AGI Media probe of /api/v2/service-accounts returned: 403).
  * offset paging (limit/skip, dataPath "results"): IS writes every page's records into "results"
    and keeps the vendor's totalCount, so a complete paged read is results == totalCount and a
    read cut off by maxPages is results < totalCount.

Records carry every property of the documented jumpcloud.service_accounts.ServiceAccount schema
(JumpCloud API 2.0, https://docs.jumpcloud.com/api/2.0/index.yaml).
"""
import importlib.util
from pathlib import Path

import pytest

HERE = Path(__file__).parent
INVENTORY = "isNonHumanIdentityInventoryEnabled"
SCOPED = "isAPIAccountPermissionScoped"
KEYS = [INVENTORY, SCOPED]


def load(key):
    spec = importlib.util.spec_from_file_location("jcsa_env_" + key, HERE / (key + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run(key, body):
    out = load(key).transform(body)
    info = out["additionalInfo"]
    assert info["metadata"]["schemaVersion"] == "2.0"
    assert set(info) == {"dataCollection", "validation", "transformation", "evaluation", "metadata"}
    return out["transformedResponse"][key], info["dataCollection"]["status"]


def service_account(n, role_name, role_id="5384ecab584a471a3dd0f30b"):
    record = {
        "authConfigList": [{"id": "ac-" + str(n), "type": "CLIENT_SECRET"}],
        "authType": "CLIENT_CREDENTIALS",
        "createdAt": "2026-06-0" + str(1 + n % 9) + "T14:02:11Z",
        "expiresAt": "2027-06-01T14:02:11Z",
        "name": "svc-" + str(n),
        "objectId": "66a1f0c2e4b0" + str(100000000000 + n)[-12:],
        "orgCount": 0,
        "orgId": "5f1b2c3d4e5f60718293a4b5",
        "providerId": "",
        "roleId": role_id,
        "status": "ACTIVE",
    }
    if role_name is not None:
        record["roleName"] = role_name
    return record


def is_ok(vendor_body):
    return {"result": {"apiResponse": vendor_body}}


VENDOR_403 = {"result": {
    "integrationName": "JumpCloud-Identity and Access Management",
    "errorMessage": "Forbidden",
    "vendorStatus": 403,
    "vendorUrl": "https://console.jumpcloud.com/api/v2/service-accounts?limit=100",
    "vendorError": "{\"message\": \"Forbidden\"}",
    "vendorErrorType": "forbidden",
}}
VENDOR_401 = {"result": {
    "integrationName": "JumpCloud-Identity and Access Management",
    "errorMessage": "Unauthorized",
    "vendorStatus": 401,
    "vendorUrl": "https://console.jumpcloud.com/api/v2/service-accounts?limit=100",
    "vendorError": "{\"message\": \"Unauthorized\"}",
    "vendorErrorType": "unauthorized",
}}


@pytest.mark.parametrize("key", KEYS)
@pytest.mark.parametrize("body", [VENDOR_403, VENDOR_401, is_ok(None), is_ok({}), {"result": {}}],
                         ids=["vendor_403", "vendor_401", "ok_null", "ok_empty_dict", "result_empty"])
def test_is_error_envelopes_are_unevaluated(key, body):
    assert run(key, body) == (None, "error")


@pytest.mark.parametrize("key", KEYS)
def test_paged_read_cut_short_is_unevaluated(key):
    records = [service_account(i, "Read Only") for i in range(100)]
    assert run(key, is_ok({"totalCount": 150, "results": records})) == (None, "error")


def test_inventory_pass_on_full_paged_read():
    records = [service_account(i, "Read Only") for i in range(150)]
    assert run(INVENTORY, is_ok({"totalCount": 150, "results": records})) == (True, "success")


def test_inventory_fail_on_complete_empty_read():
    assert run(INVENTORY, is_ok({"totalCount": 0, "results": []})) == (False, "success")


def test_scoped_pass_on_full_paged_read_of_scoped_roles():
    roles = ["Read Only", "Help Desk", "Manager", "Command Runner", "SIEM export (custom)"]
    records = [service_account(i, roles[i % len(roles)]) for i in range(150)]
    assert run(SCOPED, is_ok({"totalCount": 150, "results": records})) == (True, "success")


def test_scoped_fail_names_the_full_admin_account():
    records = [service_account(1, "Read Only"), service_account(2, "Administrator With Billing")]
    out = load(SCOPED).transform(is_ok({"totalCount": 2, "results": records}))
    assert out["transformedResponse"][SCOPED] is False
    assert any("svc-2" in r for r in out["additionalInfo"]["evaluation"]["failReasons"])


def test_scoped_empty_inventory_is_unevaluated():
    assert run(SCOPED, is_ok({"totalCount": 0, "results": []})) == (None, "error")


def test_scoped_role_id_only_is_unevaluated():
    # roleName is DEPRECATED in the vendor schema; a record carrying only roleId is not guessed at.
    records = [service_account(1, "Read Only"), service_account(2, None)]
    assert run(SCOPED, is_ok({"totalCount": 2, "results": records})) == (None, "error")


@pytest.mark.parametrize("key", KEYS)
def test_string_body_is_parsed(key):
    import json
    body = json.dumps(is_ok({"totalCount": 1, "results": [service_account(1, "Read Only")]}))
    assert run(key, body) == (True, "success")
