"""WI-3a members-outside rule in entra_ca_mfa_coverage.py (isRDPProtected, isMFARequiredForRemoteAccess) and
ismfaenforcedforusers.py (isMFAEnforcedForUsers). The sandbox forces two copies of the rule, so the same synthetic
fixtures run through both and must leave the same members outside. Also: an account a FULL block policy covers cannot sign
in remotely (not outside), a narrow block (legacy auth, one country) reaches nobody, and per-user MFA (read by
ismfaenforcedforusers.py only) enforced for the members outside keeps that key from failing."""
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
SVC = load("areserviceaccountsinteractivesigninblocked")
U = ["b0000000-0000-0000-0000-00000000000%d" % i for i in range(1, 7)]  # 6 enabled members
G_SVC = "d0000000-0000-0000-0000-000000000001"
G_STAFF = "d0000000-0000-0000-0000-000000000002"
G_PAIR = "d0000000-0000-0000-0000-000000000003"
ROLE_ADMIN = "62e90394-69f5-4237-9190-012177145e10"


def pol(name, grant=("mfa",), include_users=(), include_groups=(), exclude_users=(), exclude_groups=(), roles=(),
        risk=(), state="enabled", apps=("All",), client=("all",), locations=None, exclude_locations=None):
    cond = {"users": {"includeUsers": list(include_users), "includeGroups": list(include_groups),
                      "excludeUsers": list(exclude_users), "excludeGroups": list(exclude_groups),
                      "includeRoles": list(roles), "excludeRoles": []},
            "applications": {"includeApplications": list(apps)}, "clientAppTypes": list(client),
            "signInRiskLevels": list(risk)}
    if locations is not None:
        cond["locations"] = {"includeLocations": list(locations)}
    if exclude_locations is not None:
        cond["locations"] = {"includeLocations": list(locations or ["All"]), "excludeLocations": list(exclude_locations)}
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


SVC_GROUP = (G_SVC, U[3:6])
STAFF = (G_STAFF, U[:3])
MFA_EXCL_SVC = pol("MFA all users", include_users=["All"], exclude_groups=[G_SVC])
BLOCK_SVC = pol("Block service accounts", grant=("block",), include_groups=[G_SVC])
LEGACY_BLOCK = pol("Block legacy auth", grant=("block",), include_users=["All"],
                   client=("exchangeActiveSync", "other"))
GEO_BLOCK = pol("Block one country", grant=("block",), include_users=["All"], locations=["named-location-id"])
def block_all(*exclude, exclude_groups=()):
    return pol("Block all", grant=("block",), include_users=["All"], exclude_locations=list(exclude),
               exclude_groups=list(exclude_groups))


G_BIG = "d0000000-0000-0000-0000-000000000004"


MFA_STAFF = pol("MFA staff", include_groups=[G_STAFF])
CASES = {
    "block-all-no-exclusion": ([MFA_STAFF, block_all()], [STAFF], set()),
    "block-all-exclude-none": ([MFA_STAFF, block_all("none")], [STAFF], set()),
    "block-all-exclude-alltrusted": ([MFA_STAFF, block_all("AllTrusted")], [STAFF], set()),
    "block-all-exclude-home-country": ([MFA_STAFF, block_all("country-id")], [STAFF], None),
    "block-all-exclude-alltrusted-and-country": ([MFA_STAFF, block_all("AllTrusted", "country-id")], [STAFF], None),
    # a named exclusion is named whatever the location condition says: break-glass credit applies to a maybe block too
    "block-all-exclude-country-excludes-break-glass": ([MFA_STAFF, block_all("country-id", exclude_groups=[G_PAIR])],
                                                       [(G_STAFF, U[:4]), (G_PAIR, U[4:6])], set()),
    # members no policy reaches and the maybe block does not reach either are a measured gap: FAIL, never undecided
    "block-all-exclude-country-excludes-big-group": ([pol("MFA staff", include_groups=[G_STAFF]),
                                                      block_all("country-id", exclude_groups=[G_BIG])],
                                                     [(G_STAFF, U[:2]), (G_BIG, U[3:6])], set(U[3:6])),
    # the maybe-blocked service account must not push the break-glass pair over the cap: whether it is blocked decides the answer
    "maybe-block-of-named-service-account-keeps-break-glass-credit": (
        [pol("MFA all", include_users=["All"], exclude_users=[U[3], U[4], U[5]]),
         pol("Block svc", grant=("block",), include_users=[U[5]], exclude_locations=["country-id"])], [], None),
    "legacy-auth-block-all-users": ([pol("MFA staff", include_groups=[G_STAFF]), LEGACY_BLOCK], [STAFF], set(U[3:])),
    "geo-block-all-users": ([pol("MFA staff", include_groups=[G_STAFF]), GEO_BLOCK], [STAFF], set(U[3:])),
    "full-block-all-users": ([pol("MFA staff", include_groups=[G_STAFF]),
                              pol("Block all", grant=("block",), include_users=["All"])], [STAFF], set()),
    "all-users-mfa": ([pol("MFA", include_users=["All"])], [], set()),
    "group-mfa-staff": ([pol("MFA staff", include_groups=[G_STAFF])], [STAFF], set(U[3:])),
    "excluded-svc-group-no-block": ([MFA_EXCL_SVC], [SVC_GROUP], set(U[3:])),
    "excluded-svc-group-blocked": ([MFA_EXCL_SVC, BLOCK_SVC], [SVC_GROUP], set()),
    "block-by-name": ([pol("MFA", include_users=["All"], exclude_users=[U[5]]),
                       pol("Block", grant=("block",), include_users=[U[5]])], [], set()),
    "break-glass-pair-excluded": ([pol("MFA", include_users=["All"], exclude_groups=[G_PAIR])],
                                  [(G_PAIR, U[:2])], set()),
    "risk-only-policy": ([pol("MFA risky", include_users=["All"], risk=["high"])], [], set(U)),
    "disabled-block": ([MFA_EXCL_SVC, pol("Block", grant=("block",), include_groups=[G_SVC], state="disabled")],
                       [SVC_GROUP], set(U[3:])),
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


@pytest.mark.parametrize("name", ["block-all-exclude-country-excludes-break-glass",
                                  "block-all-exclude-country-excludes-big-group"])
def test_a_maybe_block_keeps_break_glass_credit_and_never_hides_a_measured_gap(name):
    b = body(*CASES[name][:2])
    want = CASES[name][2]
    for value in (run_cov(b)[0], run_cov(b, "isRDPProtected")[0], run_ismfa(b)[0]):
        assert (value is False) == bool(want)
    assert (run_cov(b)[0] is not False) == (not want)


def test_a_maybe_blocked_service_account_never_makes_the_break_glass_pair_a_confident_fail():
    b = body(*CASES["maybe-block-of-named-service-account-keeps-break-glass-credit"][:2])
    assert run_cov(b)[0] is None and run_cov(b, "isRDPProtected")[0] is None and run_ismfa(b)[0] is None


@pytest.mark.parametrize("excluded", [["country-id"], ["AllTrusted", "country-id"]])
def test_block_excluding_a_named_location_is_undecided_in_every_key(excluded):
    b = body([MFA_STAFF, block_all(*excluded)], [STAFF])
    for key in ("isRDPProtected", "isMFARequiredForRemoteAccess"):
        assert run_cov(b, key)[0] is None
    assert run_ismfa(b)[0] is None
    for _, why in (outside_cov(b), outside_ismfa(b)):
        assert "named location that was not read" in why


def test_block_excluding_a_named_location_never_hides_a_failure_it_does_not_reach():
    # the block reaches only STAFF (already covered by MFA); the other members are outside for sure
    b = body([MFA_STAFF, pol("Block staff", grant=("block",), include_groups=[G_STAFF], exclude_locations=["country-id"])],
             [STAFF])
    assert run_cov(b)[0] is False and run_ismfa(b)[0] is False


def test_excluded_group_covered_by_a_block_policy_is_not_a_failure():
    b = body([MFA_EXCL_SVC, BLOCK_SVC], [SVC_GROUP])
    for key in ("isRDPProtected", "isMFARequiredForRemoteAccess"):
        assert run_cov(b, key)[0] is not False
    assert run_ismfa(b)[0] is not False


def test_same_exclusion_without_a_block_policy_fails_with_the_count_and_new_advice():
    b = body([MFA_EXCL_SVC], [SVC_GROUP])
    value, out = run_cov(b)
    text = " ".join(out["additionalInfo"]["evaluation"]["failReasons"])
    assert value is False and "3 of 6 enabled member accounts" in text and "block them from sign-in" in text
    assert "target the policy at All users" not in text
    value, out = run_ismfa(b)
    text = " ".join(out["additionalInfo"]["evaluation"]["failReasons"] + out["additionalInfo"]["evaluation"]["recommendations"])
    assert value is False and "block them from sign-in" in text and "per-user MFA was not read" in text


@pytest.mark.parametrize("name", ["legacy-auth-block-all-users", "geo-block-all-users"])
def test_a_narrow_block_policy_does_not_hide_the_members_outside_failure(name):
    b = body(CASES[name][0], CASES[name][1])
    assert run_cov(b)[0] is False and run_cov(b, "isRDPProtected")[0] is False and run_ismfa(b)[0] is False


@pytest.mark.parametrize("change", [
    {"applications": {"includeApplications": ["All"], "excludeApplications": ["app-id"]}},
    {"applications": {"includeApplications": ["app-id"]}},
    {"applications": {"includeApplications": ["All"], "applicationFilter": {"rule": "x"}}},
    {"platforms": {"includePlatforms": ["android"]}},
    {"platforms": {"includePlatforms": ["all"], "excludePlatforms": ["iOS"]}},
    {"devices": {"deviceFilter": {"mode": "include", "rule": "x"}}},
    {"authenticationFlows": {"transferMethods": "deviceCodeFlow"}},
    {"insiderRiskLevels": "elevated"},
    {"signInRiskLevels": ["high"]},
])
def test_any_narrowing_condition_makes_a_block_policy_not_a_full_block(change):
    block = pol("Block", grant=("block",), include_users=["All"])
    block["conditions"].update(change)
    for mod in (COV, ISMFA):
        assert mod.full_block_reach(block) is False
    assert COV.full_block_reach(pol("Block", grant=("block",), include_users=["All"])) is True
    all_types = pol("Block", grant=("block",), include_users=["All"],
                    client=("browser", "mobileAppsAndDesktopClients", "exchangeActiveSync", "other"))
    all_types["conditions"]["locations"] = {"includeLocations": ["All"], "excludeLocations": ["AllTrusted"]}
    assert COV.full_block_reach(all_types) is ISMFA.full_block_reach(all_types) is True


def test_per_user_mfa_enforced_for_the_members_outside_keeps_isMFAEnforcedForUsers_from_failing():
    staff = [pol("MFA staff", include_groups=[G_STAFF])]
    enforced = per_user({u: "enforced" for u in U[3:]})
    assert run_ismfa(body(staff, [STAFF], perUserMfaStates=enforced))[0] is not False
    # a state that is neither enforced nor disabled ("enabled") is undecided: still not a False
    partial = per_user(dict({u: "enforced" for u in U[3:5]}, **{U[5]: "enabled"}))
    assert run_ismfa(body(staff, [STAFF], perUserMfaStates=partial))[0] is None
    # all disabled: measured, so it fails
    disabled = per_user({u: "disabled" for u in U[3:]})
    assert run_ismfa(body(staff, [STAFF], perUserMfaStates=disabled))[0] is False
    # a per-user read that was cut off or errored never fails
    for bad in ({"error": {"code": "x"}}, {"value": [{"id": U[3], "perUserMfaState": "enforced"}], "@odata.nextLink": "n"}):
        assert run_ismfa(body(staff, [STAFF], perUserMfaStates=bad))[0] is None


def test_the_one_click_file_does_not_read_per_user_mfa_and_says_it_may_apply():
    b = body([pol("MFA staff", include_groups=[G_STAFF])], [STAFF], perUserMfaStates=per_user({u: "enforced" for u in U[3:]}))
    value, out = run_cov(b)
    assert value is False and "per-user MFA is not read here" in " ".join(out["additionalInfo"]["evaluation"]["failReasons"])


def test_security_defaults_enabled_keeps_the_members_outside_from_failing_in_both_files():
    b = body([pol("MFA staff", include_groups=[G_STAFF])], [STAFF],
             securityDefaults={"@odata.context": "https://graph.microsoft.com/v1.0/$metadata#policies/"
                                                 "identitySecurityDefaultsEnforcementPolicy/$entity",
                               "id": "00000000-0000-0000-0000-000000000005", "isEnabled": True})
    assert run_cov(b)[0] is None and run_ismfa(b)[0] is None


def _block(change=None, client=("all",), locs=None):
    p = pol("Block", grant=("block",), include_users=["All"], client=client)
    p["conditions"].update(change or {})
    if locs is not None:
        p["conditions"]["locations"] = {"includeLocations": ["All"], "excludeLocations": list(locs)}
    return p


MATRIX = (
    [_block(c) for c in (
        {"applications": {"includeApplications": ["All"], "excludeApplications": ["app-id"]}},
        {"applications": {"includeApplications": ["app-id"]}},
        {"applications": {"includeApplications": ["All"], "applicationFilter": {"rule": "x"}}},
        {"platforms": {"includePlatforms": ["android"]}},
        {"platforms": {"includePlatforms": ["all"], "excludePlatforms": ["iOS"]}},
        {"devices": {"deviceFilter": {"mode": "include", "rule": "x"}}},
        {"authenticationFlows": {"transferMethods": "deviceCodeFlow"}},
        {"insiderRiskLevels": "elevated"},
        {"signInRiskLevels": ["high"]},
        {"clientApplications": {"includeServicePrincipals": ["All"]}},
        {"someFutureCondition": {"include": ["x"]}},
        {"someFutureCondition": {"include": []}},
        {"devices": {"deviceFilter": None}},
        {"signInRiskLevels": ["high", "medium", "low", "none"]},
        {"@odata.type": "#microsoft.graph.conditionalAccessConditionSet"},
        {"@odata.type": "#microsoft.graph.conditionalAccessConditionSet", "devices": {"deviceFilter": {"rule": "x"}}},
    )]
    + [_block(client=c) for c in (("browser",), ("browser", "mobileAppsAndDesktopClients"),
                                  ("browser", "mobileAppsAndDesktopClients", "exchangeActiveSync", "other"),
                                  ("exchangeActiveSync", "other"), ("all",), ())]
    + [_block(locs=e) for e in ([], ["none"], ["AllTrusted"], ["country-id"], ["AllTrusted", "country-id"])]
    + [_block({"locations": {"includeLocations": ["named-location-id"]}})]
)


@pytest.mark.parametrize("index", range(len(MATRIX)))
def test_the_three_files_share_one_definition_of_a_full_block(index):
    policy = MATRIX[index]
    assert COV.full_block_reach(policy) == ISMFA.full_block_reach(policy) == SVC.full_block(policy)
    assert COV.full_block_reach(policy) in (True, None, False)


def test_an_odata_annotation_on_conditions_is_not_a_narrowing_condition_in_any_file():
    block = pol("Block", grant=("block",), include_users=["All"])
    block["conditions"]["@odata.type"] = "#microsoft.graph.conditionalAccessConditionSet"
    assert COV.full_block_reach(block) is ISMFA.full_block_reach(block) is SVC.full_block(block) is True
    # a full block covers every member: nobody is outside, in both MFA copies
    b = body([block], [])
    assert not outside_cov(b)[0] and not outside_ismfa(b)[0]
    for out in (run_cov(b)[1], run_ismfa(b)[1]):
        assert "covered by no enabled" not in str(out)
