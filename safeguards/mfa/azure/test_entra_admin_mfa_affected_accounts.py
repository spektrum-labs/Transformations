"""Microsoft Entra ID: admin MFA findings name the affected accounts (#101, the role-level gap).

isMFAEnforcedForAdmins and isMFAConfiguredForSecurityAdmins judge Conditional Access at role level. When the
workflow also merges the directory role assignments (roleAssignments) and the MFA registration report
(registrationDetails), the first reason names the active role holders that are in a role no enforced policy
covers or have no MFA method registered: at most 20, then "and N more", inside one line that names the tool
and its scope. inputSummary.affectedAccounts carries at most 50, with the full count in affectedAccountCount.
Verdicts never change, with or without the new reads. Synthetic data only (x.test users, zero-filled object
ids; role template ids are Microsoft's public ids). Each case runs as plain Python and in the Token-Service
sandbox replica.
"""
import copy
import importlib.util
import pathlib

import pytest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]
TAG = "entra101gap"

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
ADMINS = "ismfaenforcedforadmins"
SECADMINS = "ismfaconfiguredforsecurityadmins"
GLOBAL_ADMIN = "62e90394-69f5-4237-9190-012177145e10"
SECURITY_ADMIN = "194ae4cb-b126-40b2-bd5b-6091b380977d"
EXCHANGE_ADMIN = "29232cdf-9323-42fd-ade2-1d097af3e4de"
NO_PREMIUM = {"error": {"code": "Authentication_RequestFromNonPremiumTenantOrB2CTenant",
                        "message": "Neither tenant is B2C or tenant doesn't have premium license"}}


def load(name, mode):
    path = HERE / (name + ".py")
    if mode == "sandbox":
        return load_code(path.read_text(), "<transformation>")["transform"]
    spec = importlib.util.spec_from_file_location(TAG + "_" + name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def oid(n):
    return "00000000-0000-0000-0000-%012d" % n


def upn(n):
    return "admin%03d@x.test" % n


def policy(roles, state="enabled"):
    return {"displayName": "MFA for admins", "state": state, "grantControls": {"builtInControls": ["mfa"]},
            "conditions": {"applications": {"includeApplications": ["All"]},
                           "users": {"includeUsers": [], "includeRoles": roles, "excludeRoles": []}}}


def ca(roles):
    return {"value": [policy(roles)]}


def assign(role, n, kind=None):
    row = {"roleDefinitionId": role, "principalId": oid(n)}
    if kind:
        row["principal"] = {"@odata.type": "#microsoft.graph." + kind, "id": oid(n)}
    return row


def reg(n, registered):
    return {"id": oid(n), "userPrincipalName": upn(n), "isAdmin": True, "isMfaRegistered": registered,
            "methodsRegistered": ["microsoftAuthenticatorPush"] if registered else [], "userType": "member"}


def admins_input(roles_covered, defaults=False, assignments=None, registration=None):
    body = {"conditionalAccessPolicies": ca(roles_covered), "securityDefaults": {"isEnabled": defaults}}
    if assignments is not None:
        body["roleAssignments"] = assignments
        body["registrationDetails"] = registration
    return body


def secadmins_input(roles_covered, assignments=None, registration=None):
    if assignments is None:
        return ca(roles_covered)
    return {"conditionalAccessPolicies": ca(roles_covered), "roleAssignments": assignments,
            "registrationDetails": registration}


def info(out):
    return out["additionalInfo"]


def first_reason(out):
    ev = info(out)["evaluation"]
    return (ev["failReasons"] or ev["passReasons"])[0]


def summary(out):
    return info(out)["transformation"]["inputSummary"]


def without_time(out):
    out = copy.deepcopy(out)
    out["additionalInfo"]["metadata"].pop("evaluatedAt", None)
    return out


# ---- isMFAEnforcedForAdmins ----

@pytest.mark.parametrize("mode", MODES)
def test_admins_fail_names_uncovered_then_unregistered(mode):
    assignments = {"value": [assign(GLOBAL_ADMIN, 1), assign(EXCHANGE_ADMIN, 2), assign(EXCHANGE_ADMIN, 3),
                             assign(GLOBAL_ADMIN, 4)]}
    registration = {"value": [reg(1, False), reg(2, True), reg(3, False), reg(4, True)]}
    out = load(ADMINS, mode)(admins_input([GLOBAL_ADMIN], assignments=assignments, registration=registration))
    assert out["transformedResponse"]["isMFAEnforcedForAdmins"] is False
    assert out["transformedResponse"]["adminRolesCovered"] == 1
    assert "affectedAccounts" not in out["transformedResponse"]
    assert summary(out)["affectedAccounts"] == [upn(3), upn(2), upn(1)]
    assert summary(out)["affectedAccountCount"] == 3
    assert first_reason(out).endswith(
        "; Microsoft Entra ID (active holders of the 14 admin roles): 3 of 4 admin role holders lack enforced or "
        "registered MFA (2 in a role no enforced policy covers, 2 with no MFA method registered): "
        + upn(3) + ", " + upn(2) + ", " + upn(1))


@pytest.mark.parametrize("mode", MODES)
def test_admins_pass_names_unregistered_holders(mode):
    assignments = {"value": [assign(GLOBAL_ADMIN, 1), assign(EXCHANGE_ADMIN, 2)]}
    registration = {"value": [reg(1, True), reg(2, False)]}
    out = load(ADMINS, mode)(admins_input([], defaults=True, assignments=assignments, registration=registration))
    assert out["transformedResponse"]["isMFAEnforcedForAdmins"] is True
    assert summary(out)["affectedAccounts"] == [upn(2)]
    assert "0 in a role no enforced policy covers, 1 with no MFA method registered): " + upn(2) in first_reason(out)


@pytest.mark.parametrize("mode", MODES)
def test_admins_clean_pass_names_no_one(mode):
    assignments = {"value": [assign(GLOBAL_ADMIN, 1)]}
    out = load(ADMINS, mode)(admins_input([], defaults=True, assignments=assignments,
                                          registration={"value": [reg(1, True)]}))
    assert out["transformedResponse"]["isMFAEnforcedForAdmins"] is True
    assert summary(out)["affectedAccounts"] == []
    assert summary(out)["affectedAccountCount"] == 0
    assert "Microsoft Entra ID (" not in first_reason(out)


@pytest.mark.parametrize("mode", MODES)
def test_admins_cap_50_and_20_named(mode):
    assignments = {"value": [assign(EXCHANGE_ADMIN, n) for n in range(1, 61)]}
    registration = {"value": [reg(n, True) for n in range(1, 61)]}
    out = load(ADMINS, mode)(admins_input([GLOBAL_ADMIN], assignments=assignments, registration=registration))
    assert len(summary(out)["affectedAccounts"]) == 50
    assert summary(out)["affectedAccountCount"] == 60
    reason = first_reason(out)
    assert upn(20) + " and 40 more" in reason
    assert upn(21) not in reason


@pytest.mark.parametrize("mode", MODES)
def test_admins_licence_403_names_by_role_only(mode):
    assignments = {"value": [assign(EXCHANGE_ADMIN, 1), assign(GLOBAL_ADMIN, 2)]}
    out = load(ADMINS, mode)(admins_input([GLOBAL_ADMIN], assignments=assignments, registration=NO_PREMIUM))
    assert out["transformedResponse"]["isMFAEnforcedForAdmins"] is False
    assert summary(out)["affectedAccounts"] == [oid(1)]
    assert "MFA registration not read (the report needs Entra ID P1 or P2)" in first_reason(out)


@pytest.mark.parametrize("mode", MODES)
def test_admins_truncated_reads_are_flagged(mode):
    assignments = {"value": [assign(EXCHANGE_ADMIN, 1)], "@odata.nextLink": "https://graph.microsoft.com/v1.0/next"}
    registration = {"value": [reg(1, True)], "@odata.nextLink": "https://graph.microsoft.com/v1.0/next"}
    out = load(ADMINS, mode)(admins_input([GLOBAL_ADMIN], assignments=assignments, registration=registration))
    reason = first_reason(out)
    assert "the role assignment list is partial (unread pages)" in reason
    assert "the registration report is partial (unread pages)" in reason


@pytest.mark.parametrize("mode", MODES)
def test_admins_missing_user_group_and_service_principal(mode):
    assignments = {"value": [assign(EXCHANGE_ADMIN, 1), assign(EXCHANGE_ADMIN, 7),
                             assign(EXCHANGE_ADMIN, 8, "group"), assign(EXCHANGE_ADMIN, 9, "servicePrincipal")]}
    out = load(ADMINS, mode)(admins_input([GLOBAL_ADMIN], assignments=assignments,
                                          registration={"value": [reg(1, True)]}))
    assert summary(out)["affectedAccounts"] == [upn(1), oid(7), "group:" + oid(8)]
    assert "1 role holder(s) are not in the registration report" in first_reason(out)


@pytest.mark.parametrize("mode", MODES)
def test_admins_unread_role_assignments_say_so(mode):
    out = load(ADMINS, mode)(admins_input([GLOBAL_ADMIN], assignments={"error": {"code": "Authorization_RequestDenied"}},
                                          registration={"value": []}))
    assert out["transformedResponse"]["isMFAEnforcedForAdmins"] is False
    assert "affectedAccounts" not in summary(out)
    assert "accounts not named, the directory role assignments were not read" in first_reason(out)


@pytest.mark.parametrize("mode", MODES)
def test_admins_without_new_reads_is_unchanged(mode):
    plain = load(ADMINS, mode)(admins_input([GLOBAL_ADMIN]))
    assert "affectedAccounts" not in summary(plain)
    assert "Microsoft Entra ID (" not in first_reason(plain)
    named = load(ADMINS, mode)(admins_input([GLOBAL_ADMIN], assignments={"value": [assign(EXCHANGE_ADMIN, 1)]},
                                            registration={"value": [reg(1, False)]}))
    assert named["transformedResponse"] == plain["transformedResponse"]
    assert info(named)["dataCollection"] == info(plain)["dataCollection"]


@pytest.mark.parametrize("mode", MODES)
def test_admins_fail_closed_paths_name_no_one(mode):
    body = {"conditionalAccessPolicies": {"error": "x"}, "securityDefaults": {"isEnabled": True},
            "roleAssignments": {"value": [assign(GLOBAL_ADMIN, 1)]}, "registrationDetails": {"value": [reg(1, False)]}}
    out = load(ADMINS, mode)(body)
    assert out["transformedResponse"]["isMFAEnforcedForAdmins"] is None
    assert info(out)["dataCollection"]["status"] == "error"
    assert "affectedAccounts" not in summary(out)


# ---- isMFAConfiguredForSecurityAdmins ----

@pytest.mark.parametrize("mode", MODES)
def test_secadmins_one_role_fails_and_names_uncovered_role_holders(mode):
    assignments = {"value": [assign(GLOBAL_ADMIN, 1), assign(SECURITY_ADMIN, 2), assign(EXCHANGE_ADMIN, 3)]}
    registration = {"value": [reg(1, True), reg(2, True), reg(3, False)]}
    out = load(SECADMINS, mode)(secadmins_input([GLOBAL_ADMIN], assignments, registration))
    assert out["transformedResponse"]["isMFAConfiguredForSecurityAdmins"] is False
    assert out["transformedResponse"]["coveredRoles"] == ["Global Administrator"]
    assert summary(out)["affectedAccounts"] == [upn(2)]
    assert first_reason(out).endswith(
        "; Microsoft Entra ID (active holders of the security admin roles this check targets): 1 of 2 security "
        "admin role holders lack enforced or registered MFA (1 in a role no enforced policy covers, 0 with no MFA "
        "method registered): " + upn(2))


@pytest.mark.parametrize("mode", MODES)
def test_secadmins_fail_names_every_holder(mode):
    assignments = {"value": [assign(GLOBAL_ADMIN, 1), assign(SECURITY_ADMIN, 2)]}
    registration = {"value": [reg(1, True), reg(2, False)]}
    out = load(SECADMINS, mode)(secadmins_input([], assignments, registration))
    assert out["transformedResponse"]["isMFAConfiguredForSecurityAdmins"] is False
    assert summary(out)["affectedAccounts"] == [upn(2), upn(1)]
    assert first_reason(out).startswith("0 of 6 security admin roles require MFA through an enabled Conditional "
                                        "Access policy; not covered: Global Administrator, ")
    assert "; Microsoft Entra ID (" in first_reason(out)


@pytest.mark.parametrize("mode", MODES)
def test_secadmins_licence_403_and_cap(mode):
    assignments = {"value": [assign(SECURITY_ADMIN, n) for n in range(1, 56)]}
    out = load(SECADMINS, mode)(secadmins_input([GLOBAL_ADMIN], assignments, NO_PREMIUM))
    assert len(summary(out)["affectedAccounts"]) == 50
    assert summary(out)["affectedAccountCount"] == 55
    reason = first_reason(out)
    assert oid(20) + " and 35 more" in reason
    assert "MFA registration not read" in reason


@pytest.mark.parametrize("mode", MODES)
def test_secadmins_bare_policy_list_is_unchanged(mode):
    transform = load(SECADMINS, mode)
    plain = transform(secadmins_input([GLOBAL_ADMIN]))
    wrapped = transform({"conditionalAccessPolicies": secadmins_input([GLOBAL_ADMIN]),
                         "roleAssignments": {"value": []}, "registrationDetails": {"value": []}})
    assert wrapped["transformedResponse"] == plain["transformedResponse"]
    assert "affectedAccounts" not in summary(plain)
    assert summary(wrapped)["affectedAccounts"] == []
    plain_again = transform(secadmins_input([GLOBAL_ADMIN]))
    assert without_time(plain_again) == without_time(plain)


@pytest.mark.parametrize("mode", MODES)
def test_secadmins_wrapped_body_unwraps_like_bare(mode):
    transform = load(SECADMINS, mode)
    body = {"apiResponse": secadmins_input([SECURITY_ADMIN])}
    plain = transform(body)
    wrapped = transform({"conditionalAccessPolicies": body, "roleAssignments": {"value": [assign(SECURITY_ADMIN, 1)]},
                         "registrationDetails": {"value": [reg(1, True)]}})
    assert wrapped["transformedResponse"] == plain["transformedResponse"]
    assert summary(wrapped)["affectedAccounts"] == []
