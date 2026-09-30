"""Microsoft Azure Key Vault Managed HSM (Encryption): isPurgeProtectionEnabled, isPublicNetworkAccessDisabled.

Fixtures follow the list response on https://learn.microsoft.com/en-us/rest/api/keyvault/managedhsm/managed-hsms/list-by-subscription?view=rest-keyvault-managedhsm-2024-11-01 .
"""
import importlib.util
from pathlib import Path

import pytest


def load(name):
    spec = importlib.util.spec_from_file_location("mhsm_" + name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


KEYS = {
    "isPurgeProtectionEnabled": [
        "properties.enablePurgeProtection",
        True,
        False
    ],
    "isPublicNetworkAccessDisabled": [
        "properties.publicNetworkAccess",
        "Disabled",
        "Enabled"
    ]
}
MODULES = {k: load(k) for k in KEYS}


def set_path(target, path, value):
    parts = path.split(".")
    for part in parts[:-1]:
        target = target.setdefault(part, {})
    target[parts[-1]] = value


def resource(i, overrides=None):
    r = {"id": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.KeyVault/managedHSMs/r%d" % i,
         "name": "r%d" % i, "type": "Microsoft.KeyVault/managedHSMs", "location": "eastus", "properties": {}}
    for key, (path, good, bad) in KEYS.items():
        set_path(r, path, good)
    for path, value in (overrides or {}).items():
        set_path(r, path, value)
    return r


def listing(*items, **extra):
    body = {"value": list(items)}
    body.update(extra)
    return body


def run(key, payload):
    out = MODULES[key].transform(payload)
    return out["transformedResponse"][key], out["additionalInfo"]["dataCollection"]["status"]


@pytest.mark.parametrize("key", sorted(KEYS))
def test_every_resource_compliant(key):
    assert run(key, listing(resource(1), resource(2))) == (True, "success")


@pytest.mark.parametrize("key", sorted(KEYS))
def test_one_non_compliant_resource_fails(key):
    path, good, bad = KEYS[key]
    body = listing(resource(1), resource(2, {path: bad}))
    assert run(key, body) == (False, "success")
    assert MODULES[key].transform(body)["transformedResponse"]["resourceCount"] == 2


NO_EVIDENCE = {
    "null": None,
    "empty_dict": {},
    "empty_string": "",
    "arm_403": {"error": {"code": "AuthorizationFailed", "message": "does not have authorization to perform action"}},
    "auth_401": {"statusCode": 401, "error": "Unauthorized"},
    "unrelated": {"hello": "world"},
    "no_resources": {"value": []},
}


@pytest.mark.parametrize("name", sorted(NO_EVIDENCE))
@pytest.mark.parametrize("key", sorted(KEYS))
def test_no_evidence_is_unevaluated(key, name):
    assert run(key, NO_EVIDENCE[name]) == (None, "error")


@pytest.mark.parametrize("key", sorted(KEYS))
def test_paged_list_is_unevaluated(key):
    body = listing(resource(1), nextLink="https://management.azure.com/next?$skiptoken=x")
    assert run(key, body) == (None, "error")


@pytest.mark.parametrize("key", sorted(KEYS))
def test_missing_field_is_unevaluated(key):
    path, good, bad = KEYS[key]
    r = resource(1)
    node = r
    parts = path.split(".")
    for part in parts[:-1]:
        node = node[part]
    del node[parts[-1]]
    assert run(key, listing(r)) == (None, "error")
