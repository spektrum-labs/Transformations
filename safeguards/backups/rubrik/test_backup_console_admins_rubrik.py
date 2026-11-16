"""Rubrik Security Cloud areBackupConsoleAdminsDedicated: fixtures from the RSC GraphQL schema (type User,
UserDomainEnum, type Group, Role.isOrgAdmin). Names are synthetic (example.com)."""
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


def group(gid, roles=None):
    return {"groupId": gid, "roles": [VIEWER] if roles is None else roles}


def body(nodes, has_next=False, end=None, count=None, truncated=None, groups=None, groups_next=False):
    info = {"hasNextPage": has_next, "endCursor": end}
    if truncated is not None:
        info["truncated"] = truncated
    groups = [] if groups is None else groups
    return {"data": {
        "usersInCurrentAndDescendantOrganization": {
            "count": len(nodes) if count is None else count, "pageInfo": info, "nodes": nodes},
        "groupsInCurrentAndDescendantOrganization": {
            "count": len(groups), "pageInfo": {"hasNextPage": groups_next, "endCursor": "c9" if groups_next else None},
            "nodes": groups}}}


#: One person administers through a local console account and keeps an everyday SSO identity with no admin role.
PASSING = body([
    user("owner@example.com", domain="LOCAL", owner=True, roles=[]),
    user("jdoe@example.com", domain="LOCAL"),
    user("jdoe@example.com", roles=[VIEWER]),
    user("svc-client", domain="CLIENT"),
    user("former@example.com", status="DEACTIVATED"),
], groups=[group("g-viewers")])

#: The flip: the same person's SSO identity also holds the administrator role.
FAILING = body([
    user("jdoe@example.com", domain="LOCAL"),
    user("jane.doe@example.com"),
])


@pytest.mark.parametrize("loader", [load_plain, load_sandboxed])
def test_separate_identities_pass(loader):
    out = run(PASSING, loader)
    assert out["transformedResponse"][KEY] is True
    s = out["additionalInfo"]["transformation"]["inputSummary"]
    assert (s["consoleAdministrators"], s["localConsoleAccounts"], s["nonPersonAccounts"]) == (3, 2, 1)
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"


@pytest.mark.parametrize("loader", [load_plain, load_sandboxed])
def test_sso_admin_not_evaluated(loader):
    out = run(FAILING, loader)
    assert out["transformedResponse"][KEY] is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"
    assert "1 of 2 console administrators sign in with an SSO or LDAP identity" in \
        out["additionalInfo"]["evaluation"]["failReasons"][0]


@pytest.mark.parametrize("name", ["adm-jdoe@example.com", "jdoe.admin@example.com", "a-jdoe@example.com",
                                  "jdoe@admin.example.com", "svc-backup@example.com"])
@pytest.mark.parametrize("domain", ["SSO", "LDAP"])
def test_admin_names_no_longer_prove_dedication(name, domain):
    assert value(body([user(name, domain=domain)])) is None


@pytest.mark.parametrize("domain", ["LOCAL", "CLIENT", "PAT", "SUPPORT"])
def test_separate_or_non_person_domains_pass(domain):
    assert value(body([user("jane.doe@example.com", domain=domain)])) is True


def test_unknown_domain_not_evaluated():
    assert value(body([user("jdoe@example.com", domain="NEWKIND")])) is None
    assert value(body([user("jdoe@example.com", domain=None)])) is None


def test_admin_group_not_evaluated():
    out = run(body([user("jdoe@example.com", domain="LOCAL")], groups=[group("g1"), group("g2", roles=[ADMIN])]))
    assert out["transformedResponse"][KEY] is None
    assert out["additionalInfo"]["transformation"]["inputSummary"]["adminGroups"] == 1
    assert "1 SSO or directory group(s) hold an RSC administrator role" in out["additionalInfo"]["evaluation"]["failReasons"][0]


def test_group_named_admin_role_counts():
    custom = {"id": "r-c", "name": "Backup Admins", "isOrgAdmin": False}
    assert value(body([user("jdoe@example.com", domain="LOCAL")], groups=[group("g1", roles=[custom])])) is None


def test_group_read_missing_or_partial_not_evaluated():
    b = body([user("jdoe@example.com", domain="LOCAL")])
    del b["data"]["groupsInCurrentAndDescendantOrganization"]
    assert value(b) is None
    b = body([user("jdoe@example.com", domain="LOCAL")])
    b["data"]["groupsInCurrentAndDescendantOrganization"] = None
    assert value(b) is None
    assert value(body([user("jdoe@example.com", domain="LOCAL")], groups=[group("g1")], groups_next=True)) is None
    b = body([user("jdoe@example.com", domain="LOCAL")], groups=[group("g1")])
    b["data"]["groupsInCurrentAndDescendantOrganization"]["count"] = 3
    assert value(b) is None
    b = body([user("jdoe@example.com", domain="LOCAL")], groups=[group("g1")])
    del b["data"]["groupsInCurrentAndDescendantOrganization"]["nodes"][0]["roles"]
    assert value(b) is None


def test_group_graphql_error_not_evaluated():
    b = body([user("jdoe@example.com", domain="LOCAL")])
    b["data"]["groupsInCurrentAndDescendantOrganization"] = None
    b["errors"] = [{"message": "Not authorized", "path": ["groupsInCurrentAndDescendantOrganization"]}]
    out = run(b)
    assert out["transformedResponse"][KEY] is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"


def test_wrapped_same_answers():
    assert value(ts_wrap(PASSING)) is True
    assert value(ts_wrap(FAILING)) is None
    assert value(json.dumps(PASSING)) is True
    assert value(json.dumps(FAILING)) is None


def test_partial_pages_not_evaluated():
    local = user("jdoe@example.com", domain="LOCAL")
    assert value(body([local], has_next=True, end="c1")) is None
    assert value(body([local], truncated=True)) is None
    assert value(body([local], count=5)) is None


def test_graphql_error_not_evaluated():
    out = run({"data": {"usersInCurrentAndDescendantOrganization": None},
               "errors": [{"message": "Not authorized", "path": ["usersInCurrentAndDescendantOrganization"]}]})
    assert out["transformedResponse"][KEY] is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"


def test_no_admin_in_read_not_evaluated():
    assert value(body([user("jdoe@example.com", roles=[VIEWER])])) is None
    assert value(body([])) is None


def test_missing_roles_not_evaluated():
    node = user("jdoe@example.com", domain="LOCAL")
    del node["roles"]
    assert value(body([node])) is None


def test_deactivated_directory_admin_ignored():
    assert value(body([user("jdoe@example.com", domain="LOCAL"), user("jane.doe@example.com", status="DEACTIVATED")])) is True


def test_account_owner_on_sso_not_evaluated():
    assert value(body([user("jane.doe@example.com", owner=True, roles=[])])) is None


def test_reasons_and_summary_carry_no_identities():
    """C4: reason text and evidence are shown to customers, so they carry counts, never names or addresses."""
    bodies = [PASSING, FAILING, body([user("jane.doe@example.com", domain="NEWKIND")]),
              body([user("jdoe@example.com", domain="LOCAL")], groups=[group("g-secret-name", roles=[ADMIN])])]
    for b in bodies:
        text = json.dumps(run(b)["additionalInfo"])
        for ident in ("example.com", "jdoe", "jane", "svc-client", "g-secret-name", "owner@"):
            assert ident not in text, (ident, text)


def test_rubrik_answers_true_or_none_only():
    """Rubrik never returns False: nothing in the RSC read shows that a directory identity is a person's everyday
    sign-in."""
    bodies = [PASSING, FAILING, body([user("jane.doe@example.com", domain="LDAP")]),
              body([user("jane.doe@example.com", owner=True, roles=[])]),
              body([user("jdoe@example.com", domain="LOCAL")], groups=[group("g", roles=[ADMIN])])]
    for b in bodies:
        assert value(b) in (True, None)


def test_merged_pages_need_a_count():
    nodes = [user("jdoe@example.com", domain="LOCAL")]
    merged = body(nodes, has_next=True, end=None)
    assert value(merged) is True
    del merged["data"]["usersInCurrentAndDescendantOrganization"]["count"]
    assert value(merged) is None
    merged["data"]["usersInCurrentAndDescendantOrganization"]["count"] = "1"
    assert value(merged) is None
    assert value(body(nodes, has_next=True, end=None, count=2)) is None


def test_count_still_optional_on_a_single_page():
    b = body([user("jdoe@example.com", domain="LOCAL")])
    del b["data"]["usersInCurrentAndDescendantOrganization"]["count"]
    assert value(b) is True


@pytest.mark.parametrize("role_name,counts", [
    ("Non-Admin Viewer", False), ("No Admin Access", False), ("Admin Read Only", False), ("Read-Only Admin", False),
    ("ReadOnlyAdmin", False), ("Administration Viewer", False), ("Viewer", False),
    ("NonAdmin", False), ("View-Only Admin", False),
    ("Backup Admins", True), ("TenantAdmin", True), ("Super Admin", True), ("Administrator", True),
    ("Admin (no delete)", True), ("Backup Admin - not prod", True), ("Admin No-MFA", True),
])
def test_custom_role_name_whole_words(role_name, counts):
    custom = {"id": "r-c", "name": role_name, "isOrgAdmin": False}
    expected = None if counts else True
    assert value(body([user("jdoe@example.com", domain="LOCAL"), user("jane.doe@example.com", roles=[custom])])) is expected


def test_is_org_admin_counts_whatever_the_name():
    custom = {"id": "r-c", "name": "Viewer", "isOrgAdmin": True}
    assert value(body([user("jdoe@example.com", domain="LOCAL"), user("jane.doe@example.com", roles=[custom])])) is None


def test_group_with_no_context_roles_not_evaluated():
    out = run(body([user("jdoe@example.com", domain="LOCAL")], groups=[group("g", roles=[])]))
    assert out["transformedResponse"][KEY] is None
    assert out["additionalInfo"]["transformation"]["inputSummary"]["subOrgGroups"] == 1


def test_group_org_admin_flag_on_viewer_named_role_not_evaluated():
    role = {"id": "r", "name": "Viewer", "isOrgAdmin": True}
    assert value(body([user("jdoe@example.com", domain="LOCAL")], groups=[group("g", roles=[role])])) is None


def test_user_with_roles_only_in_sub_org_not_evaluated():
    sub = user("jdoe@example.com", domain="LOCAL", roles=[])
    sub["allOrgs"] = [{"id": "o2"}]
    out = run(body([user("owner@example.com", domain="LOCAL"), sub]))
    assert out["transformedResponse"][KEY] is None
    assert out["additionalInfo"]["transformation"]["inputSummary"]["subOrgUsers"] == 1


def test_user_without_roles_and_without_sub_orgs_still_passes():
    plain = user("jdoe@example.com", domain="LOCAL", roles=[])
    plain["allOrgs"] = []
    assert value(body([user("owner@example.com", domain="LOCAL"), plain])) is True
