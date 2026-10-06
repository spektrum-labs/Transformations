"""Veeam Service Provider Console areBackupConsoleAdminsDedicated: fixtures from the VSPC REST API v3 OpenAPI
models User (role, status, userName, profile) and LocalUserRule (name, type, contextType, roleType, enabled),
merged by the getConsoleAdmins workflow under "users" and "localUserRules". Names are synthetic."""
import importlib.util
import json
import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
FILE = os.path.join(HERE, "arebackupconsoleadminsdedicated.py")
KEY = "areBackupConsoleAdminsDedicated"

MODULE_NAME = "veeam_vspc_arebackupconsoleadminsdedicated"


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


def coll(items, total=None):
    n = len(items) if total is None else total
    return {"meta": {"pagingInfo": {"total": n, "count": len(items), "offset": 0}}, "data": items, "errors": None}


def portal_user(name, role="PortalAdministrator", status="Enabled", email=None):
    return {"instanceUid": name + "-uid", "organizationUid": "org-1", "userName": name, "role": role,
            "status": status, "profile": {"firstName": "A", "lastName": "B", "email": email}}


def rule(name, rtype="winNTUser", context="domain", role="portalAdministrator", enabled=True):
    return {"instanceUid": name + "-uid", "name": name, "type": rtype, "contextType": context,
            "roleType": role, "enabled": enabled, "mfaPolicyStatus": "enabled", "scope": []}


def merged(users, rules):
    return {"users": coll(users), "localUserRules": coll(rules)}


PASSING = merged(
    [portal_user("adm-jdoe", email="adm-jdoe@example.com"),
     portal_user("jdoe", role="CompanyLocationUser"),
     portal_user("former", status="Disabled")],
    [rule("VSPC01\\vspcadmin", context="machine"),
     rule("VSPC01\\jroe", context="machine"),
     rule("CORP\\VSPC-Admins", rtype="winNTGroup"),
     rule("CORP\\jdoe", role="readonlyOperator"),
     rule("CORP\\old", enabled=False)],
)

FAILING = merged([portal_user("adm-jdoe")], [rule("CORP\\jdoe")])

UNCLASSIFIED = merged([portal_user("jdoe", role="CompanyOwner", email="jdoe@example.com")],
                      [rule("VSPC01\\vspcadmin", context="machine")])


@pytest.mark.parametrize("loader", [load_plain, load_sandboxed])
def test_dedicated_admins_pass(loader):
    out = run(PASSING, loader)
    assert out["transformedResponse"][KEY] is True
    assert out["additionalInfo"]["transformation"]["inputSummary"]["consoleAdministrators"] == 4


@pytest.mark.parametrize("loader", [load_plain, load_sandboxed])
def test_everyday_domain_admin_fails(loader):
    assert run(FAILING, loader)["transformedResponse"][KEY] is False


def test_unmarked_portal_admin_not_evaluated():
    out = run(UNCLASSIFIED)
    assert out["transformedResponse"][KEY] is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"


def test_wrapped_same_answers():
    assert value(ts_wrap(PASSING)) is True
    assert value(ts_wrap(FAILING)) is False


def test_missing_part_not_evaluated():
    assert value({"users": coll([portal_user("adm-jdoe")])}) is None
    assert value({"localUserRules": coll([rule("VSPC01\\vspcadmin", context="machine")])}) is None


def test_partial_page_not_evaluated():
    assert value({"users": coll([portal_user("adm-jdoe")], total=7),
                  "localUserRules": coll([])}) is None


def test_part_error_not_evaluated():
    denied = {"meta": None, "data": None, "errors": [{"message": "Access denied", "type": "security", "code": 1100}]}
    assert value({"users": coll([portal_user("adm-jdoe")]), "localUserRules": denied}) is None


def test_no_admin_not_evaluated():
    assert value(merged([portal_user("jdoe", role="CompanyLocationUser")], [])) is None
