"""Google - MFA Directory checks: findings name the affected accounts (#101).

Same shape as mfa/azure/legacyauthblocked.py (#891): the first reason names at most 20 accounts, then
"and N more", inside one line that names the tool and its scope; inputSummary.affectedAccounts carries at
most 50, with the full count in affectedAccountCount. The verdict is unchanged. Synthetic users only
(example.com). Each case runs as plain Python and in the Token-Service sandbox replica.
"""
import importlib.util
import pathlib

import pytest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]
TAG = "gmfa101"

try:
    import RestrictedPython  # noqa: F401
    _spec = importlib.util.spec_from_file_location("restricted_sandbox_" + TAG, ROOT / "tools" / "restricted_sandbox.py")
    _sandbox = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_sandbox)
    load_code = _sandbox.load
except ImportError:
    def load_code(code, filename):
        ns = {"__name__": TAG + "_sandbox"}
        exec(compile(code, filename, "exec"), ns)
        return ns

MODES = ["python", "sandbox"]


def load(name, mode):
    path = HERE / (name + ".py")
    if mode == "sandbox":
        return load_code(path.read_text(), "<transformation>")["transform"]
    spec = importlib.util.spec_from_file_location(TAG + "_" + name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def user(n, admin="False", enrolled="True", enforced="True"):
    email = "user%03d@example.com" % n
    return {"id": "1%020d" % n, "primaryEmail": email, "isAdmin": admin, "isEnrolledIn2Sv": enrolled,
            "isEnforcedIn2Sv": enforced, "suspended": "False", "archived": "False"}


def body(users):
    return {"apiResponse": {"kind": "admin#directory#users", "users": users}}


# (file, key, factory for an affected account, factory for a clean one, tool and scope, phrase)
CASES = [
    ("workspaceusermfaenforcementpercentage", "workspaceUserMfaEnforcementPercentage",
     lambda n: user(n, enforced="False"), lambda n: user(n), "Google Workspace (active users)",
     "users do not have 2-Step Verification enforced"),
    ("workspaceusermfaenrollmentpercentage", "workspaceUserMfaEnrollmentPercentage",
     lambda n: user(n, enrolled="False"), lambda n: user(n), "Google Workspace (active users)",
     "users are not enrolled in 2-Step Verification"),
    ("mfaexemptuseraccountscount", "mfaExemptUserAccountsCount",
     lambda n: user(n, enrolled="False", enforced="False"), lambda n: user(n), "Google Workspace (active users)",
     "users have no 2-Step Verification enrolled or enforced"),
    ("superadminaccountswithoutmfacount", "superAdminAccountsWithoutMfaCount",
     lambda n: user(n, admin="True", enforced="False"), lambda n: user(n, admin="True"),
     "Google Workspace (active super admins)", "super admins have no 2-Step Verification enforced"),
    ("issuperadminmfafullyenforced", "isSuperAdminMfaFullyEnforced",
     lambda n: user(n, admin="True", enforced="False"), lambda n: user(n, admin="True"),
     "Google Workspace (active super admins)", "super admins have no 2-Step Verification enforced"),
]
EXPECTED = {
    # verdict for (3 affected + 3 clean) and for (60 affected + 1 clean)
    "workspaceUserMfaEnforcementPercentage": (50.0, 1.64),
    "workspaceUserMfaEnrollmentPercentage": (50.0, 1.64),
    "mfaExemptUserAccountsCount": (3, 60),
    "superAdminAccountsWithoutMfaCount": (3, 60),
    "isSuperAdminMfaFullyEnforced": (False, False),
}


def run(name, mode, users):
    return load(name, mode)(body(users))


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("case", CASES, ids=[c[0] for c in CASES])
def test_affected_accounts_listed_and_summary_line(case, mode):
    name, key, bad, good, scope, phrase = case
    users = [bad(1), bad(2), bad(3), good(4), good(5), good(6)]
    out = run(name, mode, users)
    assert out["transformedResponse"][key] == EXPECTED[key][0]
    summary = out["additionalInfo"]["transformation"]["inputSummary"]
    assert summary["affectedAccounts"] == ["user001@example.com", "user002@example.com", "user003@example.com"]
    assert summary["affectedAccountCount"] == 3
    first = out["additionalInfo"]["evaluation"]["failReasons"][0]
    total = 6
    assert (scope + ": 3 of %d " % total + phrase + ": user001@example.com, user002@example.com, "
            "user003@example.com") in first
    assert "more" not in first
    assert "user004@example.com" not in first
    assert "affectedAccounts" not in out["transformedResponse"]


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("case", CASES, ids=[c[0] for c in CASES])
def test_cap_fifty_in_summary_twenty_in_reason(case, mode):
    name, key, bad, good, scope, phrase = case
    users = [bad(n) for n in range(1, 61)] + [good(99)]
    out = run(name, mode, users)
    assert out["transformedResponse"][key] == EXPECTED[key][1]
    summary = out["additionalInfo"]["transformation"]["inputSummary"]
    assert len(summary["affectedAccounts"]) == 50
    assert summary["affectedAccountCount"] == 60
    first = out["additionalInfo"]["evaluation"]["failReasons"][0]
    assert scope + ": 60 of 61 " + phrase + ": " in first
    assert first.count("@example.com") == 20
    assert first.endswith("and 40 more")


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("case", CASES, ids=[c[0] for c in CASES])
def test_clean_population_names_no_one(case, mode):
    name, key, bad, good, scope, phrase = case
    out = run(name, mode, [good(1), good(2)])
    summary = out["additionalInfo"]["transformation"]["inputSummary"]
    assert summary["affectedAccounts"] == []
    assert summary["affectedAccountCount"] == 0
    assert out["additionalInfo"]["evaluation"]["failReasons"] == []


@pytest.mark.parametrize("mode", MODES)
def test_overlong_identifier_is_truncated(mode):
    long_user = user(1, enforced="False")
    long_user["primaryEmail"] = "x" * 300 + "@example.com"
    out = run("workspaceusermfaenforcementpercentage", mode, [long_user, user(2)])
    assert out["additionalInfo"]["transformation"]["inputSummary"]["affectedAccounts"] == ["x" * 100]
    assert "x" * 101 not in out["additionalInfo"]["evaluation"]["failReasons"][0]
