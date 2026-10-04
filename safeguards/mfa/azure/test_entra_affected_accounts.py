"""Microsoft Entra ID: findings name the affected accounts (#101).

areAdminAccountsSeparate names the privileged role holders that hold a mailbox or productivity licence.
isMFAEnforcedForUsers names the users, groups and roles that the Conditional Access MFA policies name but none
of them covers (per-principal coverage, the rule legacyauthblocked.py uses), and the MFA scope when no policy
targets all users. The verdict comes from the transform's shipped switches (EXCLUDE_RISK_CONDITIONED,
ALL_USERS_TARGET_MODE, 4 Oct 2026): only the policies that still count feed the naming. The scope line and the
50-name cap are reachable only with ALL_USERS_TARGET_MODE = "off", so those two cases set it. Same shape as legacyauthblocked.py (#891): the first reason names at most 20, then
"and N more", inside one line that names the tool and its scope; inputSummary.affectedAccounts carries at most
50, with the full count in affectedAccountCount. Verdicts are unchanged. Synthetic data only (example.com
users, zero-filled object ids). Each case runs as plain Python and in the Token-Service sandbox replica.
"""
import importlib.util
import pathlib
import re

import pytest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]
TAG = "entra101"

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
GLOBAL_ADMIN = "62e90394-69f5-4237-9190-012177145e10"
SPE_E3 = "05e9a617-0261-4cee-bb44-138d3ef5d965"
ENTRA_P2 = "84a661c4-e949-4bd2-a560-ed7766fcaf2b"


def load(name, mode, **switches):
    """switches override module-level constants (for example ALL_USERS_TARGET_MODE="off")."""
    path = HERE / (name + ".py")
    if mode == "sandbox":
        code = path.read_text()
        for key, value in switches.items():
            code, n = re.subn(r"(?m)^" + key + r" = .*$", key + " = " + repr(value), code)
            assert n == 1, key
        return load_code(code, "<transformation>")["transform"]
    spec = importlib.util.spec_from_file_location(TAG + "_" + name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for key, value in switches.items():
        assert hasattr(module, key), key
        setattr(module, key, value)
    return module.transform


def oid(n):
    return "00000000-0000-0000-0000-%012d" % n


def info(out):
    return out["additionalInfo"]


# ---- areAdminAccountsSeparate ----

def admin_user(n, mailbox):
    return {"id": oid(n), "userPrincipalName": "admin%03d@example.com" % n, "mail": None,
            "assignedLicenses": [{"disabledPlans": [], "skuId": SPE_E3 if mailbox else ENTRA_P2}],
            "assignedPlans": []}


def admins_body(users):
    return {"roleAssignments": {"value": [{"roleDefinitionId": GLOBAL_ADMIN, "principalId": u["id"]} for u in users]},
            "users": {"value": users}}


@pytest.mark.parametrize("mode", MODES)
def test_admin_separation_names_licensed_admins(mode):
    users = [admin_user(1, True), admin_user(2, False), admin_user(3, True)]
    out = load("areadminaccountsseparate", mode)(admins_body(users))
    assert out["transformedResponse"]["areAdminAccountsSeparate"] is False
    assert out["transformedResponse"]["adminsWithMailLicense"] == 2
    assert "affectedAccounts" not in out["transformedResponse"]
    summary = info(out)["transformation"]["inputSummary"]
    assert summary["affectedAccounts"] == ["admin001@example.com", "admin003@example.com"]
    assert summary["affectedAccountCount"] == 2
    first = info(out)["evaluation"]["failReasons"][0]
    assert first == ("2 of 3 admin account(s) have mail/Exchange Online licenses; Microsoft Entra ID (privileged "
                     "directory roles): 2 of 3 admin accounts hold a mailbox or productivity licence: "
                     "admin001@example.com, admin003@example.com")


@pytest.mark.parametrize("mode", MODES)
def test_admin_separation_cap(mode):
    users = [admin_user(n, True) for n in range(1, 61)]
    out = load("areadminaccountsseparate", mode)(admins_body(users))
    assert out["transformedResponse"]["areAdminAccountsSeparate"] is False
    summary = info(out)["transformation"]["inputSummary"]
    assert len(summary["affectedAccounts"]) == 50
    assert summary["affectedAccountCount"] == 60
    first = info(out)["evaluation"]["failReasons"][0]
    assert first.count("@example.com") == 20
    assert first.endswith("and 40 more")


@pytest.mark.parametrize("mode", MODES)
def test_admin_separation_pass_names_no_one(mode):
    out = load("areadminaccountsseparate", mode)(admins_body([admin_user(1, False)]))
    assert out["transformedResponse"]["areAdminAccountsSeparate"] is True
    assert info(out)["transformation"]["inputSummary"]["affectedAccounts"] == []
    assert "Microsoft Entra ID (" not in info(out)["evaluation"]["passReasons"][0]


# ---- isMFAEnforcedForUsers ----

def ca_policy(include_users=None, include_groups=None, exclude_users=None, exclude_groups=None, state="enabled"):
    return {"id": oid(9000), "displayName": "Require MFA", "state": state,
            "conditions": {"users": {"includeUsers": ["All"] if include_users is None else include_users,
                                     "excludeUsers": exclude_users or [], "includeGroups": include_groups or [],
                                     "excludeGroups": exclude_groups or [], "includeRoles": [], "excludeRoles": []}},
            "grantControls": {"operator": "OR", "builtInControls": ["mfa"]}}


def mfa_body(*policies):
    return {"authMethodsPolicy": {"authenticationMethodConfigurations": [
        {"id": "MicrosoftAuthenticator", "state": "enabled"}]},
        "conditionalAccessPolicies": {"value": list(policies)}}


@pytest.mark.parametrize("mode", MODES)
def test_mfa_users_names_uncovered_principals(mode):
    # Two All-users policies, each excluding two accounts (within MAX_EXCLUDED_ACCOUNTS, so both count):
    # oid(2) is excluded by both, oid(1) and oid(4) are covered by the other policy.
    out = load("ismfaenforcedforusers", mode)(mfa_body(
        ca_policy(exclude_users=[oid(1), oid(2)]),
        ca_policy(exclude_users=[oid(2), oid(4)])))
    assert out["transformedResponse"]["isMFAEnforcedForUsers"] is True
    assert "affectedAccounts" not in out["transformedResponse"]
    summary = info(out)["transformation"]["inputSummary"]
    assert summary["affectedAccounts"] == ["user:" + oid(2)]
    assert summary["affectedAccountCount"] == 1
    assert "mfaScope" not in summary
    first = info(out)["evaluation"]["passReasons"][0]
    assert first.startswith("MFA methods enabled: MicrosoftAuthenticator; ")
    assert first.endswith("Microsoft Entra ID (Conditional Access policies requiring MFA for users): 1 of 3 users, "
                          "groups or roles named in those policies are covered by none of them: user:" + oid(2))
    assert oid(1) not in first and oid(4) not in first
    assert info(out)["evaluation"]["recommendations"]


@pytest.mark.parametrize("mode", MODES)
def test_mfa_users_set_aside_policies_stay_unevaluated_and_name_no_one(mode):
    # Shipped switches: a group-scoped policy, or an All-users policy excluding a group, is set aside and the
    # check is not evaluated, exactly as before #101; nothing is named.
    for policy in (ca_policy(include_users=[], include_groups=[oid(8)]),
                   ca_policy(exclude_users=[oid(1)], exclude_groups=[oid(3)])):
        out = load("ismfaenforcedforusers", mode)(mfa_body(policy))
        assert out["transformedResponse"]["isMFAEnforcedForUsers"] is None
        summary = info(out)["transformation"]["inputSummary"]
        assert "affectedAccounts" not in summary and "mfaScope" not in summary


@pytest.mark.parametrize("mode", MODES)
def test_mfa_users_cap(mode):
    out = load("ismfaenforcedforusers", mode, ALL_USERS_TARGET_MODE="off")(mfa_body(ca_policy(exclude_users=[oid(n) for n in range(100, 160)])))
    assert out["transformedResponse"]["isMFAEnforcedForUsers"] is True
    summary = info(out)["transformation"]["inputSummary"]
    assert len(summary["affectedAccounts"]) == 50
    assert summary["affectedAccountCount"] == 60
    first = info(out)["evaluation"]["passReasons"][0]
    assert ": 60 of 60 users, groups or roles" in first
    assert first.count("user:") == 20
    assert first.endswith("and 40 more")


@pytest.mark.parametrize("mode", MODES)
def test_mfa_users_group_scoped_policy_names_scope(mode):
    out = load("ismfaenforcedforusers", mode, ALL_USERS_TARGET_MODE="off")(mfa_body(ca_policy(include_users=[], include_groups=[oid(8)])))
    assert out["transformedResponse"]["isMFAEnforcedForUsers"] is True
    summary = info(out)["transformation"]["inputSummary"]
    assert summary["affectedAccountCount"] == 0
    assert summary["mfaScope"] == ["group:" + oid(8)]
    assert info(out)["evaluation"]["passReasons"][0].endswith(
        "; no MFA policy targets all users, MFA reaches only: group:" + oid(8))


@pytest.mark.parametrize("mode", MODES)
def test_mfa_users_all_users_no_exclusions_names_no_one(mode):
    out = load("ismfaenforcedforusers", mode)(mfa_body(ca_policy()))
    assert out["transformedResponse"]["isMFAEnforcedForUsers"] is True
    assert info(out)["transformation"]["inputSummary"]["affectedAccounts"] == []
    assert info(out)["evaluation"]["passReasons"][0] == "MFA methods enabled: MicrosoftAuthenticator"
    assert info(out)["evaluation"]["recommendations"] == []


@pytest.mark.parametrize("mode", MODES)
def test_mfa_users_disabled_policy_exclusions_do_not_leak(mode):
    out = load("ismfaenforcedforusers", mode)(mfa_body(ca_policy(), ca_policy(state="disabled", exclude_users=[oid(5)])))
    assert oid(5) not in str(info(out)["evaluation"]) + str(info(out)["transformation"])
