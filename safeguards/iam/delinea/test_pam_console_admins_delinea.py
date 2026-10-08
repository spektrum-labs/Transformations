"""Delinea Secret Server arePAMConsoleAdminsDedicated (IAM-004).

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
    spec = importlib.util.spec_from_file_location("delinea_" + name, HERE / (name + ".py"))
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
    ('arepamconsoleadminsdedicated', 'arePAMConsoleAdminsDedicated', 'console_admins_roles_unread.json', None),
    ('arepamconsoleadminsdedicated', 'arePAMConsoleAdminsDedicated', 'console_admins_roles_partial_page.json', None),
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


# --- per-user roles bodies: paging and user-id matching ---------------------------------------

KEY = "arePAMConsoleAdminsDedicated"
MODULE = "arepamconsoleadminsdedicated"


def dedicated():
    return fixture("console_admins_dedicated.json")


def keyed(body, swap=False):
    ids = [u["id"] for u in body["records"]]
    if swap:
        ids[1], ids[2] = ids[2], ids[1]
    body["userRoles"] = [{"userId": ids[i], "roles": body["userRoles"][i]} for i in range(len(ids))]
    return body


def roles_total_above_rows(body):
    body["userRoles"][2]["total"] = 3
    return body


def body_user_id_mismatch(body):
    body["userRoles"][2]["userId"] = 999
    return body


def body_user_id_match(body):
    for i in range(len(body["records"])):
        body["userRoles"][i]["userId"] = body["records"][i]["id"]
    return body


def keyed_list_roles(body):
    body = keyed(body)
    for entry in body["userRoles"]:
        entry["roles"] = entry["roles"]["records"]
    return body


ROLE_CASES = [
    ("roles total above rows", roles_total_above_rows, None),
    ("keyed entries, ids match", keyed, True),
    ("keyed entries, ids swapped", lambda b: keyed(b, swap=True), None),
    ("keyed entries, roles as a bare list", keyed_list_roles, True),
    ("body userId mismatch", body_user_id_mismatch, None),
    ("body userId match", body_user_id_match, True),
]


@pytest.mark.parametrize("loader", LOADERS, ids=["plain", "sandbox"])
@pytest.mark.parametrize("label,mutate,expected", ROLE_CASES, ids=[c[0] for c in ROLE_CASES])
def test_roles_paging_and_user_match(loader, label, mutate, expected):
    value, status = verdict(loader(MODULE)(mutate(dedicated())), KEY)
    assert value is expected
    assert status == ("error" if expected is None else "success")
