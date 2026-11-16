"""WI-3a members-outside rule in entra_ca_mfa_coverage.py (isRDPProtected, isMFARequiredForRemoteAccess) and
ismfaenforcedforusers.py (isMFAEnforcedForUsers). The sandbox forces two copies of the rule, so the same synthetic
fixtures run through both and must leave the same members outside. Also: an account a block policy covers cannot sign
in remotely (not outside), and per-user MFA enforced for the members outside keeps the key from failing."""
import copy
import importlib.util
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location("parity_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


COV = load("entra_ca_mfa_coverage")
ISMFA = load("ismfaenforcedforusers")
U = ["b0000000-0000-0000-0000-00000000000%d" % i for i in range(1, 7)]  # 6 enabled members
G_SVC = "d0000000-0000-0000-0000-000000000001"
G_STAFF = "d0000000-0000-0000-0000-000000000002"
G_PAIR = "d0000000-0000-0000-0000-000000000003"
ROLE_ADMIN = "62e90394-69f5-4237-9190-012177145e10"


def pol(name, grant=("mfa",), include_users=(), include_groups=(), exclude_users=(), exclude_groups=(), roles=(),
        risk=(), state="enabled", apps=("All",)):
    cond = {"users": {"includeUsers": list(include_users), "includeGroups": list(include_groups),
                      "excludeUsers": list(exclude_users), "excludeGroups": list(exclude_groups),
                      "includeRoles": list(roles), "excludeRoles": []},
            "applications": {"includeApplications": list(apps)}, "clientAppTypes": ["all"],
            "signInRiskLevels": list(risk)}
    return {"id": name, "displayName": name, "state": state, "conditions": cond,
            "grantControls": {"operator": "OR", "builtInControls": list(grant)}}


def body(policies, groups, **extra):
    """groups: [(group id, [member ids])], read in this order."""
    b = {"authMethodsPolicy": {"authenticationMethodConfigurations": [{"id": "MicrosoftAuthenticator",
                                                                       "state": "enabled"}]},
         "conditionalAccessPolicies": {"@odata.context": "https://graph.microsoft.com/v1.0/$metadata#x",
                                       "value": list(policies)},
         "workforceUsers": {"value": [{"id": i, "accountEnabled": True, "userType": "Member"} for i in U]},
         "caPolicyGroups": {"groupIds": [{"id": g} for g, _ in groups]},
         "groupMembers": [{"value": [{"id": i} for i in m]} for _, m in groups]}
    b.update(extra)
    return b


def per_user(states):
    return {"value": [{"id": uid, "perUserMfaState": st} for uid, st in states.items()]}


def outside_cov(b):
    b = copy.deepcopy(b)
    workforce = COV.read_workforce(b["workforceUsers"])
    memberships = COV.read_memberships(b["caPolicyGroups"], b["groupMembers"])
    found, why = COV.members_outside(b["conditionalAccessPolicies"]["value"], workforce, memberships,
                                     b.get("roleAssignments"))
    return found, why


def outside_ismfa(b):
    b = copy.deepcopy(b)
    found, why = ISMFA.members_outside(b, b["conditionalAccessPolicies"]["value"])
    return (found["outside"] if found is not None else None), why


SVC = (G_SVC, U[3:6])
STAFF = (G_STAFF, U[:3])
MFA_EXCL_SVC = pol("MFA all users", include_users=["All"], exclude_groups=[G_SVC])
BLOCK_SVC = pol("Block service accounts", grant=("block",), include_groups=[G_SVC])
CASES = {
    "all-users-mfa": ([pol("MFA", include_users=["All"])], [], set()),
    "group-mfa-staff": ([pol("MFA staff", include_groups=[G_STAFF])], [STAFF], set(U[3:])),
    "excluded-svc-group-no-block": ([MFA_EXCL_SVC], [SVC], set(U[3:])),
    "excluded-svc-group-blocked": ([MFA_EXCL_SVC, BLOCK_SVC], [SVC], set()),
    "block-by-name": ([pol("MFA", include_users=["All"], exclude_users=[U[5]]),
                       pol("Block", grant=("block",), include_users=[U[5]])], [], set()),
    "break-glass-pair-excluded": ([pol("MFA", include_users=["All"], exclude_groups=[G_PAIR])],
                                  [(G_PAIR, U[:2])], set()),
    "risk-only-policy": ([pol("MFA risky", include_users=["All"], risk=["high"])], [], set(U)),
    "disabled-block": ([MFA_EXCL_SVC, pol("Block", grant=("block",), include_groups=[G_SVC], state="disabled")],
                       [SVC], set(U[3:])),
    "role-policy-unread": ([pol("MFA admins", roles=[ROLE_ADMIN])], [], None),
}


@pytest.mark.parametrize("name", sorted(CASES))
def test_both_files_leave_the_same_members_outside(name):
    policies, groups, expected = CASES[name]
    b = body(policies, groups)
    cov, cov_why = outside_cov(b)
    ismfa, ismfa_why = outside_ismfa(b)
    assert cov == ismfa == expected, (cov_why, ismfa_why)


def run_cov(b, key="isMFARequiredForRemoteAccess"):
    out = COV.transform(copy.deepcopy(b))
    return out["transformedResponse"][key], out


def run_ismfa(b):
    out = ISMFA.transform(copy.deepcopy(b))
    return out["transformedResponse"]["isMFAEnforcedForUsers"], out


def test_excluded_group_covered_by_a_block_policy_is_not_a_failure():
    b = body([MFA_EXCL_SVC, BLOCK_SVC], [SVC])
    for key in ("isRDPProtected", "isMFARequiredForRemoteAccess"):
        assert run_cov(b, key)[0] is not False
    assert run_ismfa(b)[0] is not False


def test_same_exclusion_without_a_block_policy_fails_with_the_count_and_new_advice():
    b = body([MFA_EXCL_SVC], [SVC])
    value, out = run_cov(b)
    text = " ".join(out["additionalInfo"]["evaluation"]["failReasons"])
    assert value is False and "3 of 6 enabled member accounts" in text and "block them from sign-in" in text
    assert "target the policy at All users" not in text
    value, out = run_ismfa(b)
    text = " ".join(out["additionalInfo"]["evaluation"]["failReasons"] + out["additionalInfo"]["evaluation"]["recommendations"])
    assert value is False and "block them from sign-in" in text and "per-user MFA was not read" in text


def test_per_user_mfa_enforced_for_the_members_outside_keeps_the_key_from_failing():
    enforced = per_user({u: "enforced" for u in U[3:]})
    b = body([pol("MFA staff", include_groups=[G_STAFF])], [STAFF], perUserMfaStates=enforced)
    assert run_cov(b)[0] is not False and run_ismfa(b)[0] is not False
    # a state that is neither enforced nor disabled ("enabled") is undecided: still not a False
    partial = per_user(dict({u: "enforced" for u in U[3:5]}, **{U[5]: "enabled"}))
    b = body([pol("MFA staff", include_groups=[G_STAFF])], [STAFF], perUserMfaStates=partial)
    assert run_cov(b)[0] is None and run_ismfa(b)[0] is None
    # all disabled: measured, so it fails
    disabled = per_user({u: "disabled" for u in U[3:]})
    b = body([pol("MFA staff", include_groups=[G_STAFF])], [STAFF], perUserMfaStates=disabled)
    value, out = run_cov(b)
    assert value is False and "per-user MFA is not read" not in " ".join(out["additionalInfo"]["evaluation"]["failReasons"])
    assert run_ismfa(b)[0] is False
    # a per-user read that was cut off or errored never fails
    for bad in ({"error": {"code": "x"}}, {"value": [{"id": U[3], "perUserMfaState": "enforced"}], "@odata.nextLink": "n"}):
        b = body([pol("MFA staff", include_groups=[G_STAFF])], [STAFF], perUserMfaStates=bad)
        assert run_cov(b)[0] is None and run_ismfa(b)[0] is None


def test_security_defaults_enabled_keeps_the_members_outside_from_failing_in_both_files():
    b = body([pol("MFA staff", include_groups=[G_STAFF])], [STAFF],
             securityDefaults={"@odata.context": "https://graph.microsoft.com/v1.0/$metadata#policies/"
                                                 "identitySecurityDefaultsEnforcementPolicy/$entity",
                               "id": "00000000-0000-0000-0000-000000000005", "isEnabled": True})
    assert run_cov(b)[0] is None and run_ismfa(b)[0] is None
