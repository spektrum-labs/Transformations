"""isLifeCycleManagementEnabled is Not evaluated when the bound read is the org factor list.

The Okta definition binds this key to a read that returns the org's authentication factors
([{factorType, provider, status, ...}]). That list says nothing about provisioning, so it is
"not measurable from this read" (None), never "Lifecycle management configuration not found".
Synthetic factor list only.
"""
import importlib.util
import pathlib

HERE = pathlib.Path(__file__).parent
KEY = "isLifeCycleManagementEnabled"
FACTORS = [
    {"id": "fac-1", "factorType": "token", "provider": "RSA", "status": "NOT_SETUP", "_links": {}},
    {"id": "fac-2", "factorType": "token:hardware", "provider": "YUBICO", "status": "ACTIVE", "_links": {}},
    {"id": "fac-3", "factorType": "push", "provider": "OKTA", "status": "ACTIVE", "_links": {}},
]


def run(body):
    spec = importlib.util.spec_from_file_location("okta_lifecycle", HERE / "islifecyclemanagementenabled.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform(body)


def test_factor_list_is_not_measurable():
    out = run(FACTORS)
    assert out["transformedResponse"][KEY] is None
    assert "not measurable from this read" in out["additionalInfo"]["evaluation"]["failReasons"][0]
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"


def test_mixed_list_is_not_treated_as_factor_list():
    assert run(FACTORS + [{"id": "app-1", "name": "provisioning"}])["transformedResponse"][KEY] is False


def test_other_shapes_unchanged():
    assert run({"enabled": True})["transformedResponse"][KEY] is True
    assert run({"enabled": False})["transformedResponse"][KEY] is False
    assert run({})["transformedResponse"][KEY] is False
