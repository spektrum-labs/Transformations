"""BeyondTrust PRA arePAMConsoleAdminsDedicated (IAM-004).

Fixtures in fixtures/ are built from the vendor's documented response shape with every name,
id and account replaced (example.com, 111111111111). Each case runs twice: imported as plain
Python, and compiled and run in the production RestrictedPython sandbox (tools/restricted_sandbox.py)
when RestrictedPython is installed."""
import importlib.util
import json
import pathlib
import sys

import pytest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]

NO_EVIDENCE = [{}, None, "{}", "", {"error": {"type": "authentication_error"}},
               {"statusCode": 401, "error": "Unauthorized"}, {"statusCode": 403, "error": "Forbidden"},
               {"error": True, "message": "upstream timeout"}, {"hello": "world"}, {"foo": {"bar": [1, 2, 3]}}]


def plain(name):
    spec = importlib.util.spec_from_file_location("btpra_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def sandboxed(name):
    pytest.importorskip("RestrictedPython")
    sys.path.insert(0, str(ROOT / "tools"))
    import restricted_sandbox
    return restricted_sandbox.load((HERE / (name + ".py")).read_text())["transform"]


LOADERS = [plain, sandboxed]


def fixture(name):
    return json.loads((HERE / "fixtures" / name).read_text())


def verdict(out, key):
    return out["transformedResponse"][key], out["additionalInfo"]["dataCollection"]["status"]


CASES = [
    ('arepamconsoleadminsdedicated', 'arePAMConsoleAdminsDedicated', 'console_admins_dedicated.json', True),
    ('arepamconsoleadminsdedicated', 'arePAMConsoleAdminsDedicated', 'console_admins_everyday_sso.json', False),
    ('arepamconsoleadminsdedicated', 'arePAMConsoleAdminsDedicated', 'console_admins_unknown_provider.json', None),
    ('arepamconsoleadminsdedicated', 'arePAMConsoleAdminsDedicated', 'console_admins_dedicated_group_policies_unread.json', None),
    ('arepamconsoleadminsdedicated', 'arePAMConsoleAdminsDedicated', 'console_admins_group_policy_everyday.json', False),
    ('arepamconsoleadminsdedicated', 'arePAMConsoleAdminsDedicated', 'console_admins_local_only.json', True),
]


@pytest.mark.parametrize("loader", LOADERS, ids=["plain", "sandbox"])
@pytest.mark.parametrize("module,key,fixture_name,expected", CASES)
def test_fixture(loader, module, key, fixture_name, expected):
    value, status = verdict(loader(module)(fixture(fixture_name)), key)
    assert value is expected
    assert status == ("error" if expected is None else "success")


@pytest.mark.parametrize("loader", LOADERS, ids=["plain", "sandbox"])
@pytest.mark.parametrize("module,key", sorted(set((c[0], c[1]) for c in CASES)))
@pytest.mark.parametrize("body", NO_EVIDENCE, ids=[str(i) for i in range(len(NO_EVIDENCE))])
def test_no_evidence_is_not_evaluated(loader, module, key, body):
    value, status = verdict(loader(module)(body), key)
    assert value is None and status == "error"


@pytest.mark.parametrize("loader", LOADERS, ids=["plain", "sandbox"])
@pytest.mark.parametrize("module,key,fixture_name,expected", [c for c in CASES if c[3] is not None][:2])
def test_json_string_input_matches_dict(loader, module, key, fixture_name, expected):
    body = (HERE / "fixtures" / fixture_name).read_text()
    assert verdict(loader(module)(body), key)[0] is expected


# --- group-policy admin grants fail closed ---------------------------------------------------

KEY = "arePAMConsoleAdminsDedicated"
MODULE = "arepamconsoleadminsdedicated"


def dedicated():
    return fixture("console_admins_dedicated.json")


def set_policies(value):
    def mutate(body):
        body["groupPolicies"] = value
        return body
    return mutate


def grant_policy(**changes):
    def mutate(body):
        policy = body["groupPolicies"][0]
        for k, v in changes.items():
            if v is KeyError:
                policy.pop(k, None)
            else:
                policy[k] = v
        return body
    return mutate


def local_only_plus_disabled_saml_provider(body):
    body = fixture("console_admins_local_only.json")
    body["securityProviders"].append({"id": 2, "name": "Corporate SAML", "type": "saml", "enabled": False})
    return body


def everyday_without_policies(body):
    return fixture("console_admins_everyday_sso.json")


def disabled_member(body):
    body["groupPolicies"][0]["members"].append({"id": 15, "security_provider_id": 2, "user_id": 4})
    return body


POLICY_CASES = [
    ("policies empty list", set_policies([]), True),
    ("policies null", set_policies(None), None),
    ("policies error body", set_policies({"error": True, "message": "403"}), None),
    ("policies wrapped in data", lambda b: set_policies({"data": b["groupPolicies"]})(b), True),
    ("granting policy, members missing", grant_policy(members=KeyError), None),
    ("granting policy, members error", grant_policy(members={"statusCode": 403}), None),
    ("granting policy, group member", grant_policy(members=[{"id": 9, "security_provider_id": 2, "group_id": "PRA-Admins"}]), None),
    ("granting policy, unknown user id", grant_policy(members=[{"id": 9, "user_id": 77}]), None),
    ("policy without perm_admin", grant_policy(perm_admin=KeyError), None),
    ("granting policy member is a disabled user", disabled_member, True),
    ("no policies read, a disabled SAML provider exists", local_only_plus_disabled_saml_provider, None),
    ("no policies read, everyday SSO admin already found", everyday_without_policies, False),
]


@pytest.mark.parametrize("loader", LOADERS, ids=["plain", "sandbox"])
@pytest.mark.parametrize("label,mutate,expected", POLICY_CASES, ids=[c[0] for c in POLICY_CASES])
def test_group_policy_admin_grants(loader, label, mutate, expected):
    value, status = verdict(loader(MODULE)(mutate(dedicated())), KEY)
    assert value is expected
    assert status == ("error" if expected is None else "success")


@pytest.mark.parametrize("loader", LOADERS, ids=["plain", "sandbox"])
def test_unread_group_policies_reason_names_the_gap(loader):
    out = loader(MODULE)(fixture("console_admins_dedicated_group_policies_unread.json"))
    assert out["transformedResponse"][KEY] is None
    assert "group-policy admin grants were not read" in out["additionalInfo"]["dataCollection"]["errors"][0]


# --- group policies and members are paged like users: a full page or a marker is partial ------

def hundred_policies(body):
    filler = [{"id": 100 + i, "name": "Policy " + str(i), "perm_admin": False, "members": []}
              for i in range(100 - len(body["groupPolicies"]))]
    body["groupPolicies"] = body["groupPolicies"] + filler
    return body


def ninety_nine_policies(body):
    filler = [{"id": 100 + i, "name": "Policy " + str(i), "perm_admin": False, "members": []}
              for i in range(99 - len(body["groupPolicies"]))]
    body["groupPolicies"] = body["groupPolicies"] + filler
    return body


def hundred_members_on_admin_policy(body):
    """100 members on the admin-granting policy, all of them the one dedicated admin, so only the
    page-size guard can make the result anything but True."""
    body["groupPolicies"][0]["members"] = [{"id": 1000 + i, "security_provider_id": 2, "user_id": 2}
                                          for i in range(100)]
    return body


def hundred_members_on_non_admin_policy(body):
    body["groupPolicies"][1]["members"] = [{"id": 1000 + i, "security_provider_id": 2, "group_id": "g" + str(i)}
                                          for i in range(100)]
    return body


def policies_with_marker(key, value):
    def mutate(body):
        body["groupPolicies"] = {"data": body["groupPolicies"], key: value}
        return body
    return mutate


def members_with_marker(key, value):
    def mutate(body):
        body["groupPolicies"][0]["members"] = {"data": body["groupPolicies"][0]["members"], key: value}
        return body
    return mutate


def workflow_pagination_stats(body):
    body["paginationStats"] = {"groupPolicies": {"paginationTruncated": True}}
    return body


def users_with_marker(key, value):
    def mutate(body):
        body["users"] = {"data": body["users"], key: value}
        return body
    return mutate


def workflow_users_stats(body):
    body["paginationStats"] = {"users": {"paginationTruncated": True}}
    return body


def hundred_users(body):
    filler = [{"id": 500 + i, "username": "user" + str(i) + "@example.com", "enabled": True,
               "perm_admin": False, "security_provider_id": 2} for i in range(100 - len(body["users"]))]
    body["users"] = body["users"] + filler
    return body


PAGING_CASES = [
    ("100 group policies", hundred_policies, None),
    ("99 group policies", ninety_nine_policies, True),
    ("100 members on an admin policy", hundred_members_on_admin_policy, None),
    ("100 members on a non-admin policy", hundred_members_on_non_admin_policy, True),
    ("policies with next link", policies_with_marker("next", "/api/config/v1/group-policy?current_page=2"), None),
    ("policies with hasNext", policies_with_marker("hasNext", True), None),
    ("policies with NextToken", policies_with_marker("NextToken", "abc"), None),
    ("policies with empty next", policies_with_marker("next", ""), True),
    ("members with next link", members_with_marker("next", "/api/config/v1/group-policy/1/member?current_page=2"), None),
    ("members with paginationTruncated", members_with_marker("paginationTruncated", True), None),
    ("workflow paginationStats.groupPolicies truncated", workflow_pagination_stats, None),
    ("users with paginationTruncated", lambda b: users_with_marker("paginationTruncated", True)(b), None),
    ("users with next link", lambda b: users_with_marker("next", "/api/config/v1/user?current_page=2")(b), None),
    ("users with empty next", lambda b: users_with_marker("next", None)(b), True),
    ("workflow paginationStats.users truncated", workflow_users_stats, None),
    ("100 users", hundred_users, None),
]


@pytest.mark.parametrize("loader", LOADERS, ids=["plain", "sandbox"])
@pytest.mark.parametrize("label,mutate,expected", PAGING_CASES, ids=[c[0] for c in PAGING_CASES])
def test_group_policy_and_member_paging(loader, label, mutate, expected):
    value, status = verdict(loader(MODULE)(mutate(dedicated())), KEY)
    assert value is expected
    assert status == ("error" if expected is None else "success")
