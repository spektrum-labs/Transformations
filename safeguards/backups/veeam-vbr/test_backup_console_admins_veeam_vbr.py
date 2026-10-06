"""Veeam Backup & Replication areBackupConsoleAdminsDedicated: fixtures from the VBR 13 REST API 1.3
"Get All Users and Groups" model (type, roles, isServiceAccount, pagination). Names are synthetic."""
import importlib.util
import json
import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
FILE = os.path.join(HERE, "arebackupconsoleadminsdedicated.py")
KEY = "areBackupConsoleAdminsDedicated"

MODULE_NAME = "veeam_vbr_arebackupconsoleadminsdedicated"


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

BACKUP_ADMIN = {"id": "r1", "name": "Veeam Backup Administrator", "description": "Built-in role with full privileges"}
SECURITY_ADMIN = {"id": "r2", "name": "Veeam Security Administrator", "description": "Built-in role"}
RESTORE_OP = {"id": "r3", "name": "Veeam Restore Operator", "description": "Built-in role"}


def entry(name, etype="InternalUser", roles=None, service=False):
    return {"id": name, "name": name, "type": etype, "roles": [BACKUP_ADMIN] if roles is None else roles,
            "isServiceAccount": service}


def coll(items, total=None):
    n = len(items) if total is None else total
    return {"data": items, "pagination": {"total": n, "count": len(items), "skip": 0, "limit": 1000}}


PASSING = coll([
    entry("BUILTIN\\Administrators", "InternalGroup"),
    entry("VBR01\\veeamadmin"),
    entry("CORP\\adm-jdoe", roles=[SECURITY_ADMIN]),
    entry("CORP\\svc-automation", service=True),
    entry("a-jroe@example.com", "ExternalUser"),
    entry("CORP\\jdoe", roles=[RESTORE_OP]),
])

FAILING = coll([
    entry("BUILTIN\\Administrators", "InternalGroup"),
    entry("CORP\\jdoe"),
])

FAILING_GROUP = coll([entry("CORP\\Domain Users", "InternalGroup")])


@pytest.mark.parametrize("loader", [load_plain, load_sandboxed])
def test_dedicated_admins_pass(loader):
    out = run(PASSING, loader)
    assert out["transformedResponse"][KEY] is True
    assert out["additionalInfo"]["transformation"]["inputSummary"]["consoleAdministrators"] == 5


@pytest.mark.parametrize("loader", [load_plain, load_sandboxed])
def test_everyday_domain_admin_fails(loader):
    assert run(FAILING, loader)["transformedResponse"][KEY] is False


def test_general_group_fails():
    assert value(FAILING_GROUP) is False


def test_wrapped_same_answers():
    assert value(ts_wrap(PASSING)) is True
    assert value(ts_wrap(FAILING)) is False


def test_partial_page_not_evaluated():
    assert value(coll([entry("VBR01\\veeamadmin")], total=3)) is None


def test_missing_total_not_evaluated():
    assert value({"data": [entry("VBR01\\veeamadmin")], "pagination": {}}) is None


def test_vbr_error_envelope_not_evaluated():
    out = run({"errorCode": "AccessDenied", "message": "Access is denied", "resourceId": None})
    assert out["transformedResponse"][KEY] is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"


def test_no_admin_not_evaluated():
    assert value(coll([entry("CORP\\jdoe", roles=[RESTORE_OP])])) is None


def test_missing_roles_not_evaluated():
    item = entry("CORP\\adm-jdoe")
    del item["roles"]
    assert value(coll([item])) is None


def test_unknown_type_unmarked_not_evaluated():
    assert value(coll([entry("jdoe", "NewType")])) is None
