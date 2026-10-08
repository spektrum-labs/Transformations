"""CyberArk (PVWA) arePAMConsoleAdminsDedicated (IAM-004).

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
    spec = importlib.util.spec_from_file_location("cyberark_" + name, HERE / (name + ".py"))
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
    ('arepamconsoleadminsdedicated', 'arePAMConsoleAdminsDedicated', 'console_admins_no_extended_details.json', None),
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


# --- an administrator whose source is missing is not evaluated -------------------------------


def admin_without_source(value):
    body = fixture("console_admins_dedicated.json")
    for u in body["Users"]:
        if u.get("userType") == "Built-InAdmins" or "vaultAuthorization" in u:
            if value is None:
                u.pop("source", None)
            else:
                u["source"] = value
            return body
    raise AssertionError("fixture has no administrator")


@pytest.mark.parametrize("loader", LOADERS, ids=["plain", "sandbox"])
@pytest.mark.parametrize("value", [None, "", "   "], ids=["missing", "empty", "blank"])
@pytest.mark.parametrize("username", ["jdoe", "admin"])
def test_admin_without_source_is_not_evaluated(loader, value, username):
    body = admin_without_source(value)
    for u in body["Users"]:
        if "source" not in u or not str(u.get("source")).strip():
            u["username"] = username
    out = loader("arepamconsoleadminsdedicated")(body)
    assert out["transformedResponse"]["arePAMConsoleAdminsDedicated"] is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"
