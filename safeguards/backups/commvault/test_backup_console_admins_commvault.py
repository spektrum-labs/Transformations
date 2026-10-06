"""Commvault areBackupConsoleAdminsDedicated: fixtures from the V4 UserGroup detail and V4 User list shapes read
by Commvault's SDK (cvpysdk), merged by the getCommCellAdmins workflow under "masterGroup" and "users".
Names are synthetic."""
import importlib.util
import json
import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
FILE = os.path.join(HERE, "arebackupconsoleadminsdedicated.py")
KEY = "areBackupConsoleAdminsDedicated"

MODULE_NAME = "commvault_arebackupconsoleadminsdedicated"


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


def cv_user(uid, name, upn=None, enabled=True):
    return {"id": uid, "name": name, "email": upn, "userPrincipalName": upn, "enabled": enabled,
            "fullName": name, "company": {"id": 0, "name": "CommCell"}}


def merged(members, externals, users, name="master", total=None):
    return {"masterGroup": {"id": 1, "name": name, "enabled": True,
                            "users": [{"id": u["id"], "name": u["name"]} for u in members],
                            "associatedExternalGroups": [{"id": 100 + i, "name": g} for i, g in enumerate(externals)]},
            "users": {"users": users, "numberOfUsers": len(users) if total is None else total}}


ADMIN = cv_user(1, "admin")
ADM_JDOE = cv_user(2, "EXAMPLE\\adm-jdoe", "adm-jdoe@example.com")
JDOE = cv_user(3, "EXAMPLE\\jdoe", "jdoe@example.com")
CVLOCAL = cv_user(4, "backupops")
SSO_JROE = cv_user(5, "jroe@example.com", "jroe@example.com")
OLD = cv_user(6, "EXAMPLE\\olduser", enabled=False)

PASSING = merged([ADMIN, ADM_JDOE, CVLOCAL, OLD], ["EXAMPLE\\CV-Admins"], [ADMIN, ADM_JDOE, JDOE, CVLOCAL, SSO_JROE, OLD])
FAILING = merged([ADMIN, JDOE], [], [ADMIN, ADM_JDOE, JDOE])


@pytest.mark.parametrize("loader", [load_plain, load_sandboxed])
def test_dedicated_admins_pass(loader):
    out = run(PASSING, loader)
    assert out["transformedResponse"][KEY] is True
    assert out["additionalInfo"]["transformation"]["inputSummary"]["consoleAdministrators"] == 4


@pytest.mark.parametrize("loader", [load_plain, load_sandboxed])
def test_unmarked_directory_admin_not_evaluated(loader):
    assert run(FAILING, loader)["transformedResponse"][KEY] is None


def test_unmarked_sso_admin_not_evaluated():
    assert value(merged([ADMIN, SSO_JROE], [], [ADMIN, SSO_JROE])) is None


def test_general_external_group_fails():
    assert value(merged([ADMIN], ["EXAMPLE\\Domain Users"], [ADMIN])) is False


def test_wrapped_same_answers():
    assert value(ts_wrap(PASSING)) is True
    assert value(ts_wrap(FAILING)) is None


def test_group_one_not_master_not_evaluated():
    assert value(merged([ADMIN], [], [ADMIN], name="Tenant Admin")) is None


def test_member_missing_from_user_list_not_evaluated():
    assert value(merged([ADMIN, JDOE], [], [ADMIN])) is None


def test_partial_user_list_not_evaluated():
    assert value(merged([ADMIN], [], [ADMIN], total=50)) is None


def test_commvault_error_part_not_evaluated():
    body = merged([ADMIN], [], [ADMIN])
    body["users"] = {"errorCode": 5, "errorMessage": "Access denied"}
    assert value(body) is None


def test_membership_not_read_not_evaluated():
    body = merged([ADMIN], [], [ADMIN])
    del body["masterGroup"]["users"]
    del body["masterGroup"]["associatedExternalGroups"]
    assert value(body) is None


def test_unmarked_identity_reads_not_evaluated():
    out = run(FAILING)
    assert out["transformedResponse"][KEY] is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"
    assert "no admin marker" in out["additionalInfo"]["evaluation"]["failReasons"][0]
