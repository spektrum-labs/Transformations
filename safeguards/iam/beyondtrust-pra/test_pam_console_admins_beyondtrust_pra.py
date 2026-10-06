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
