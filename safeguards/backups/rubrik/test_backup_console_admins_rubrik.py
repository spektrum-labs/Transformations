"""Rubrik Security Cloud areBackupConsoleAdminsDedicated: fixtures from the RSC GraphQL schema (type User,
UserDomainEnum, Role.isOrgAdmin). Names are synthetic (example.com)."""
import importlib.util
import json
import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
FILE = os.path.join(HERE, "arebackupconsoleadminsdedicated.py")
KEY = "areBackupConsoleAdminsDedicated"

MODULE_NAME = "rubrik_arebackupconsoleadminsdedicated"


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

ADMIN = {"id": "r-admin", "name": "Administrator", "isOrgAdmin": True}
VIEWER = {"id": "r-view", "name": "Viewer", "isOrgAdmin": False}


def user(email, domain="SSO", roles=None, status="ACTIVE", owner=False):
    return {"id": email, "username": email, "email": email, "domain": domain, "status": status,
            "isAccountOwner": owner, "roles": [ADMIN] if roles is None else roles}


def body(nodes, has_next=False, end=None, count=None, truncated=None):
    info = {"hasNextPage": has_next, "endCursor": end}
    if truncated is not None:
        info["truncated"] = truncated
    return {"data": {"usersInCurrentAndDescendantOrganization": {
        "count": len(nodes) if count is None else count, "pageInfo": info, "nodes": nodes}}}


PASSING = body([
    user("owner@example.com", domain="LOCAL", owner=True, roles=[]),
    user("adm-jdoe@example.com"),
    user("jroe.admin@example.com", domain="LDAP"),
    user("svc-client", domain="CLIENT"),
    user("jdoe@example.com", roles=[VIEWER]),
    user("former@example.com", status="DEACTIVATED"),
])

FAILING = body([
    user("adm-jdoe@example.com"),
    user("jane.doe@example.com"),
])


@pytest.mark.parametrize("loader", [load_plain, load_sandboxed])
def test_dedicated_admins_pass(loader):
    out = run(PASSING, loader)
    assert out["transformedResponse"][KEY] is True
    assert out["additionalInfo"]["transformation"]["inputSummary"]["consoleAdministrators"] == 4


@pytest.mark.parametrize("loader", [load_plain, load_sandboxed])
def test_unmarked_sso_admin_not_evaluated(loader):
    out = run(FAILING, loader)
    assert out["transformedResponse"][KEY] is None
    assert "jane.doe@example.com" in out["additionalInfo"]["evaluation"]["failReasons"][0]


def test_wrapped_same_answers():
    assert value(ts_wrap(PASSING)) is True
    assert value(ts_wrap(FAILING)) is None
    assert value(json.dumps(FAILING)) is None


def test_partial_pages_not_evaluated():
    assert value(body([user("adm-jdoe@example.com")], has_next=True, end="c1")) is None
    assert value(body([user("adm-jdoe@example.com")], truncated=True)) is None
    assert value(body([user("adm-jdoe@example.com")], count=5)) is None


def test_graphql_error_not_evaluated():
    out = run({"data": {"usersInCurrentAndDescendantOrganization": None},
               "errors": [{"message": "Not authorized", "path": ["usersInCurrentAndDescendantOrganization"]}]})
    assert out["transformedResponse"][KEY] is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"


def test_no_admin_in_read_not_evaluated():
    assert value(body([user("jdoe@example.com", roles=[VIEWER])])) is None


def test_missing_roles_not_evaluated():
    node = user("jdoe@example.com")
    del node["roles"]
    assert value(body([node])) is None


def test_unknown_domain_unmarked_not_evaluated():
    assert value(body([user("jdoe@example.com", domain="NEWKIND")])) is None


def test_role_named_admin_counts():
    custom = {"id": "r-c", "name": "Backup Admins", "isOrgAdmin": False}
    assert value(body([user("jdoe@example.com", roles=[custom])])) is None


@pytest.mark.parametrize("name,expected", [
    ("adm-jdoe@example.com", True), ("jdoe-adm@example.com", True), ("a-jdoe@example.com", True),
    ("jdoe_a@example.com", True), ("adminjdoe@example.com", True), ("t0.jdoe@example.com", True),
    ("jdoe@admin.example.com", True), ("doe.a@example.com", None), ("jane.doe@example.com", None),
    ("admiral.jones@example.com", None), ("sam@example.com", None),
])
def test_identity_marker(name, expected):
    assert value(body([user(name)])) is expected


def test_unmarked_identity_reads_not_evaluated():
    out = run(FAILING)
    assert out["transformedResponse"][KEY] is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"
    assert "no admin marker" in out["additionalInfo"]["evaluation"]["failReasons"][0]
