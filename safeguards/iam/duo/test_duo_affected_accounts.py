"""Duo user and admin checks: findings name the affected accounts (#101).

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
TAG = "duo101"

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


def user(n, status="active", enrolled=True):
    return {"user_id": "DU%018d" % n, "username": "user%03d" % n, "email": "user%03d@example.com" % n,
            "status": status, "is_enrolled": enrolled,
            "phones": [{"phone_id": "DP%018d" % n, "activated": True}] if enrolled else []}


def admin(n, enrolled=True, role="Owner"):
    return {"admin_id": "DE%018d" % n, "email": "admin%03d@example.com" % n, "name": "Admin %03d" % n,
            "role": role, "phone_details": [{"activated": True}] if enrolled else [], "webauthncredentials": []}


def wrap(items):
    return {"response": items, "stat": "OK"}


def info(out):
    return out["additionalInfo"]


# ---- isMFAEnforcedForUsers: bypass and unenrolled active users ----

@pytest.mark.parametrize("mode", MODES)
def test_mfa_enforced_names_bypass_then_unenrolled(mode):
    users = [user(1), user(2, status="bypass"), user(3, enrolled=False), user(4), user(5, status="disabled", enrolled=False)]
    out = load("isMFAEnforcedForUsers", mode)(wrap(users))
    assert out["transformedResponse"]["isMFAEnforcedForUsers"] is False
    assert out["transformedResponse"]["mfaEnforcedUserPercentage"] == 50.0
    assert "affectedAccounts" not in out["transformedResponse"]
    summary = info(out)["transformation"]["inputSummary"]
    assert summary["affectedAccounts"] == ["user002", "user003"]
    assert summary["affectedAccountCount"] == 2
    first = info(out)["evaluation"]["failReasons"][0]
    assert first.startswith("2 of 4 active Duo users (50.0%) are held to MFA: 1 in bypass status, 1 not enrolled; ")
    assert first.endswith("Duo (active users): 2 of 4 active users are not held to MFA (bypass first, then not "
                          "enrolled): user002, user003")
    assert "user005" not in first


@pytest.mark.parametrize("mode", MODES)
def test_mfa_enforced_cap(mode):
    users = [user(n, enrolled=False) for n in range(1, 61)] + [user(99)]
    out = load("isMFAEnforcedForUsers", mode)(wrap(users))
    assert out["transformedResponse"]["isMFAEnforcedForUsers"] is False
    summary = info(out)["transformation"]["inputSummary"]
    assert len(summary["affectedAccounts"]) == 50
    assert summary["affectedAccountCount"] == 60
    first = info(out)["evaluation"]["failReasons"][0]
    assert "Duo (active users): 60 of 61 active users" in first
    assert first.count("user0") == 20
    assert first.endswith("and 40 more")


@pytest.mark.parametrize("mode", MODES)
def test_mfa_enforced_pass_names_no_one(mode):
    out = load("isMFAEnforcedForUsers", mode)(wrap([user(1), user(2)]))
    assert out["transformedResponse"]["isMFAEnforcedForUsers"] is True
    assert info(out)["transformation"]["inputSummary"]["affectedAccountCount"] == 0
    assert "Duo (" not in info(out)["evaluation"]["passReasons"][0]


# ---- bypassStatusUsersCount ----

@pytest.mark.parametrize("mode", MODES)
def test_bypass_count_names_accounts(mode):
    users = [user(1), user(2, status="bypass"), user(3, status="bypass"), user(4)]
    out = load("bypassStatusUsersCount", mode)(wrap(users))
    assert out["transformedResponse"]["bypassStatusUsersCount"] == 2
    summary = info(out)["transformation"]["inputSummary"]
    assert summary["affectedAccounts"] == ["user002", "user003"]
    assert summary["affectedAccountCount"] == 2
    first = info(out)["evaluation"]["passReasons"][0]
    assert first == ("Found 2 of 4 Duo user accounts with status='bypass'; Duo (all users): 2 of 4 users are in "
                     "bypass status (no second factor): user002, user003")


@pytest.mark.parametrize("mode", MODES)
def test_bypass_count_cap(mode):
    users = [user(n, status="bypass") for n in range(1, 56)]
    out = load("bypassStatusUsersCount", mode)(wrap(users))
    assert out["transformedResponse"]["bypassStatusUsersCount"] == 55
    summary = info(out)["transformation"]["inputSummary"]
    assert len(summary["affectedAccounts"]) == 50
    assert summary["affectedAccountCount"] == 55
    assert info(out)["evaluation"]["passReasons"][0].endswith("and 35 more")


@pytest.mark.parametrize("mode", MODES)
def test_bypass_count_none(mode):
    out = load("bypassStatusUsersCount", mode)(wrap([user(1)]))
    assert out["transformedResponse"]["bypassStatusUsersCount"] == 0
    assert info(out)["transformation"]["inputSummary"]["affectedAccounts"] == []
    assert info(out)["evaluation"]["passReasons"] == ["No users among the 1 retrieved have status='bypass'."]


# ---- mfaDeviceEnrollmentPercentage ----

@pytest.mark.parametrize("mode", MODES)
def test_device_enrollment_names_users_without_device(mode):
    users = [user(1), user(2, enrolled=False), user(3), user(4, enrolled=False), user(5, status="disabled", enrolled=False)]
    out = load("mfaDeviceEnrollmentPercentage", mode)(wrap(users))
    assert out["transformedResponse"]["mfaDeviceEnrollmentPercentage"] == 50.0
    summary = info(out)["transformation"]["inputSummary"]
    assert summary["affectedAccounts"] == ["user002", "user004"]
    assert summary["affectedAccountCount"] == 2
    first = info(out)["evaluation"]["failReasons"][0]
    assert first.startswith("2 of 4 active Duo users show no enrolled authentication device")
    assert first.endswith("Duo (active users): 2 of 4 active users have no MFA device enrolled: user002, user004")


@pytest.mark.parametrize("mode", MODES)
def test_device_enrollment_cap(mode):
    users = [user(n, enrolled=False) for n in range(1, 52)] + [user(99)]
    out = load("mfaDeviceEnrollmentPercentage", mode)(wrap(users))
    assert out["transformedResponse"]["mfaDeviceEnrollmentPercentage"] == 1.92
    summary = info(out)["transformation"]["inputSummary"]
    assert len(summary["affectedAccounts"]) == 50
    assert summary["affectedAccountCount"] == 51
    assert info(out)["evaluation"]["failReasons"][0].endswith("and 31 more")


# ---- superAdminMfaEnrollmentPercentage ----

@pytest.mark.parametrize("mode", MODES)
def test_super_admin_names_unenrolled(mode):
    admins = [admin(1), admin(2, enrolled=False), admin(3, enrolled=False, role="Help Desk"), admin(4)]
    out = load("superAdminMfaEnrollmentPercentage", mode)(wrap(admins))
    assert out["transformedResponse"]["superAdminMfaEnrollmentPercentage"] == 66.67
    summary = info(out)["transformation"]["inputSummary"]
    assert summary["affectedAccounts"] == ["admin002@example.com"]
    assert summary["affectedAccountCount"] == 1
    first = info(out)["evaluation"]["failReasons"][0]
    assert first == ("1 of 3 super admin accounts lack an enrolled MFA device; Duo (Owner and Administrator roles): "
                     "1 of 3 super admins have no MFA device enrolled: admin002@example.com")


@pytest.mark.parametrize("mode", MODES)
def test_super_admin_cap(mode):
    admins = [admin(n, enrolled=False, role="Administrator") for n in range(1, 71)]
    out = load("superAdminMfaEnrollmentPercentage", mode)(wrap(admins))
    assert out["transformedResponse"]["superAdminMfaEnrollmentPercentage"] == 0
    summary = info(out)["transformation"]["inputSummary"]
    assert len(summary["affectedAccounts"]) == 50
    assert summary["affectedAccountCount"] == 70
    first = info(out)["evaluation"]["failReasons"][0]
    assert first.count("@example.com") == 20
    assert first.endswith("and 50 more")
