"""Cohesity Helios areBackupConsoleAdminsDedicated: fixtures from the Helios v2 PrincipalList / Principal models
(objectClass User | Group, principalType Local | AD | SSO, roles). Names are synthetic."""
import importlib.util
import json
import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
FILE = os.path.join(HERE, "arebackupconsoleadminsdedicated.py")
KEY = "areBackupConsoleAdminsDedicated"

MODULE_NAME = "cohesity_arebackupconsoleadminsdedicated"


def load_plain():
    spec = importlib.util.spec_from_file_location(MODULE_NAME, FILE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def load_sandboxed():
    """The same file through the Token-Service RestrictedPython namespace (tools/restricted_sandbox.py)."""
    pytest.importorskip("RestrictedPython")
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import restricted_sandbox
    with open(FILE) as fh:
        return restricted_sandbox.load(fh.read())["transform"]



def run(payload, loader=load_plain):
    return loader()(payload)


def value(payload, loader=load_plain):
    return run(payload, loader)["transformedResponse"][KEY]


def ts_wrap(body):
    """How Token-Service hands an Integration-Service response to a transform."""
    return {"data": {"apiResponse": body}, "validation": {"status": "skipped", "errors": [], "warnings": []}}


NO_EVIDENCE = [
    {}, None, "", "{}", "not json",
    {"error": {"type": "authentication_error", "message": "invalid credentials"}},
    {"statusCode": 401, "error": "Unauthorized"},
    {"status_code": 401, "error": "Unauthorized"},
    {"error": {"statusCode": 401, "message": "Unauthorized"}},
    {"statusCode": 403, "error": "Forbidden"},
    {"hello": "world"},
    {"foo": {"bar": [1, 2, 3]}},
    {"data": []},
]


@pytest.mark.parametrize("body", NO_EVIDENCE)
def test_no_evidence_is_not_evaluated(body):
    out = run(body)
    assert out["transformedResponse"][KEY] is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"


@pytest.mark.parametrize("body", NO_EVIDENCE)
def test_no_evidence_is_not_evaluated_when_wrapped(body):
    assert value(ts_wrap(body)) is None


def principal(name, ptype="SSO", oclass="User", roles=None):
    return {"name": name, "sid": "S-" + name, "objectClass": oclass, "principalType": ptype,
            "roles": ["Super Admin"] if roles is None else roles}


def plist(items, total=None, token=None):
    return {"principals": items, "total": len(items) if total is None else total, "paginationToken": token}


PASSING = plist([
    principal("admin", ptype="Local"),
    principal("adm-jdoe@example.com"),
    principal("EXAMPLE\\Helios-Admins", ptype="AD", oclass="Group", roles=["Admin"]),
    principal("jdoe@example.com", roles=["Viewer"]),
])

FAILING = plist([principal("admin", ptype="Local"), principal("jane.doe@example.com", roles=["COHESITY_ADMIN"])])


@pytest.mark.parametrize("loader", [load_plain, load_sandboxed])
def test_dedicated_admins_pass(loader):
    out = run(PASSING, loader)
    assert out["transformedResponse"][KEY] is True
    assert out["additionalInfo"]["transformation"]["inputSummary"]["consoleAdministrators"] == 3


@pytest.mark.parametrize("loader", [load_plain, load_sandboxed])
def test_everyday_sso_admin_fails(loader):
    assert run(FAILING, loader)["transformedResponse"][KEY] is False


def test_general_ad_group_fails():
    assert value(plist([principal("EXAMPLE\\IT Staff", ptype="AD", oclass="Group")])) is False


def test_wrapped_same_answers():
    assert value(ts_wrap(PASSING)) is True
    assert value(ts_wrap(FAILING)) is False


def test_partial_not_evaluated():
    assert value(plist([principal("admin", ptype="Local")], token="next-page")) is None
    assert value(plist([principal("admin", ptype="Local")], total=9)) is None


def test_no_admin_not_evaluated():
    assert value(plist([principal("jdoe@example.com", roles=["Viewer"])])) is None


def test_missing_roles_not_evaluated():
    p = principal("adm-jdoe@example.com")
    del p["roles"]
    assert value(plist([p])) is None


def test_cohesity_error_not_evaluated():
    assert value({"errorCode": "KPermissionDenied", "message": "Access denied"}) is None
