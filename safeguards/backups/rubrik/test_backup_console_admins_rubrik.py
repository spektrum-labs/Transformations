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
    ("pam.smith@example.com", None), ("pam@example.com", None), ("joe.root@example.com", None),
    ("jdoe@privatebank.com", None), ("jdoe@adminsoft.com", None), ("jdoe@cityadm.gov", None),
    ("jdoe@admin.ch", None), ("administration@example.com", None), ("badmin@example.com", None),
])
def test_identity_marker(name, expected):
    assert value(body([user(name)])) is expected


def test_unmarked_identity_reads_not_evaluated():
    out = run(FAILING)
    assert out["transformedResponse"][KEY] is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"
    assert "no admin marker" in out["additionalInfo"]["evaluation"]["failReasons"][0]


# The naming rule is the same block in all five IAM-004 transforms; these rows are the same in every test file.

def load_module():
    spec = importlib.util.spec_from_file_location(MODULE_NAME + "_rule", FILE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MARKER_ROWS = [
    ("adm-jdoe@example.com", True), ("jdoe-adm@example.com", True), ("a-jdoe@example.com", True),
    ("jdoe_a@example.com", True), ("adminjdoe@example.com", True), ("admin01@example.com", True),
    ("t0.jdoe@example.com", True), ("pam-jdoe@example.com", True), ("root_backup@example.com", True),
    ("veeamadmin@example.com", True), ("jdoe@admin.example.com", True), ("jdoe@t0.corp.example", True),
    ("ADM\\jdoe", True), ("CORP-ADM\\jdoe", True),
    # personal names, not markers
    ("pam.smith@example.com", False), ("pam@example.com", False), ("joe.root@example.com", False),
    ("administration@example.com", False), ("badmin@example.com", False), ("padmin@example.com", False),
    ("jdoeadmin@example.com", False), ("doe.a@example.com", False), ("admiral.jones@example.com", False),
    # the organisation's own domain is never a marker; a domain label matches only as a whole word
    ("jdoe@privatebank.com", False), ("jdoe@adminsoft.com", False), ("jdoe@cityadm.gov", False),
    ("jdoe@admin.ch", False), ("jdoe@admin.co.uk", False), ("PRIVATECO\\jdoe", False), ("CORPADM\\jdoe", False),
]


@pytest.mark.parametrize("name,marked", MARKER_ROWS)
def test_shared_admin_marker(name, marked):
    assert load_module().has_admin_marker(name, False) is marked


@pytest.mark.parametrize("group,cls", [
    ("PRIVATECO\\Domain Users", "everyday-group"), ("CITYADM\\Staff", "everyday-group"),
    ("CORP\\Backup-Admins", "group"), ("BUILTIN\\Administrators", "group"), ("ADM\\Backup Operators", "group"),
])
def test_shared_group_marker(group, cls):
    assert load_module().classify([group], "group", "directory") == cls


#: Everyday addresses that the earlier rule read as admin accounts. Each, holding admin, reads Not evaluated.
UNMARKED_NAMES = ["pam.smith@example.com", "pam@example.com", "joe.root@example.com", "jdoe@privatebank.com",
                  "jdoe@adminsoft.com", "jdoe@cityadm.gov", "jdoe@admin.ch"]


@pytest.mark.parametrize("name", UNMARKED_NAMES)
def test_everyday_names_read_not_evaluated(name):
    assert value(body([user("adm-jdoe@example.com"), user(name)])) is None


def test_rubrik_answers_true_or_none_only():
    """Rubrik never returns False (J.J., 6 Oct 2026): the RSC user list has no groups, and an unmarked SSO or
    LDAP administrator reads Not evaluated."""
    bodies = [PASSING, FAILING, body([user("jane.doe@example.com", domain="LDAP")]),
              body([user("jane.doe@example.com", owner=True, roles=[])]),
              body([user("owner@example.com", domain="LOCAL", owner=True), user("jane.doe@example.com")])]
    for name, _ in MARKER_ROWS:
        bodies.append(body([user(name)]))
    for b in bodies:
        assert value(b) in (True, None)


def test_merged_pages_need_a_count():
    nodes = [user("adm-jdoe@example.com")]
    merged = body(nodes, has_next=True, end=None)
    assert value(merged) is True
    del merged["data"]["usersInCurrentAndDescendantOrganization"]["count"]
    assert value(merged) is None
    merged["data"]["usersInCurrentAndDescendantOrganization"]["count"] = "1"
    assert value(merged) is None
    assert value(body(nodes, has_next=True, end=None, count=2)) is None


def test_count_still_optional_on_a_single_page():
    b = body([user("adm-jdoe@example.com")])
    del b["data"]["usersInCurrentAndDescendantOrganization"]["count"]
    assert value(b) is True


@pytest.mark.parametrize("role_name,counts", [
    ("Non-Admin Viewer", False), ("No Admin Access", False), ("Admin Read Only", False), ("Read-Only Admin", False),
    ("ReadOnlyAdmin", False), ("Administration Viewer", False), ("Viewer", False),
    ("Backup Admins", True), ("TenantAdmin", True), ("Super Admin", True), ("Administrator", True),
])
def test_custom_role_name_whole_words(role_name, counts):
    custom = {"id": "r-c", "name": role_name, "isOrgAdmin": False}
    expected = None if counts else True
    assert value(body([user("adm-jdoe@example.com"), user("jane.doe@example.com", roles=[custom])])) is expected


def test_is_org_admin_counts_whatever_the_name():
    custom = {"id": "r-c", "name": "Viewer", "isOrgAdmin": True}
    assert value(body([user("adm-jdoe@example.com"), user("jane.doe@example.com", roles=[custom])])) is None
