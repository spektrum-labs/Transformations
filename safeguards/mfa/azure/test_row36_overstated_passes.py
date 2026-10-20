"""Entra MFA review, overstated passes (decision 18 Oct 2026: the verdict changes are accepted; these move some Met
controls to Failed or Not evaluated). Section 4 holds the row 36B rules from the same decision.

1. isMFAEnforcedForUsers (ismfaenforcedforusers.py): an "All users" MFA policy counts only when it applies to all
   cloud apps and is not narrowed by platform, client type, named locations or a device filter, the rule the
   group-scoped path already applies. A narrowed All-users policy is set aside and does not count; with nothing
   else counting the key reads Failed (it reaches only some sign-ins, which is a measured gap, like a risk-only
   policy).
2. legacyAuthBlocked (legacyauthblocked.py): a block counts only when the blocking policies together cover all
   users, with at most two named accounts or one group left outside (the break-glass limit, section 4) and no
   role or guest exclusion left uncovered. A block for named users only reads Failed; a block whose reach
   depends on group or role membership, or that leaves more than two accounts or guests outside, reads Not
   evaluated (membership is not read here).
3. isMFAConfiguredForSecurityAdmins (ismfaconfiguredforsecurityadmins.py): aligned with the remote-access and
   phishing-resistant checks. A policy narrowed by client app type, platform, a device filter or named locations
   only does not count (Failed when no other policy covers the role). A policy that excludes more than one group, a
   directory role, guests or more than two named accounts (in total across the counting policies) leaves coverage unproven:
   Not evaluated, not Failed. Excluded locations (all locations minus trusted ones) and excluded apps other than the
   admin surface stay findings.

Synthetic estate only (public repo); role ids are Microsoft's public built-in role template ids. Every case also
runs under the Token-Service sandbox replica.
"""
import copy
import importlib.util
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]

U1, U2, U3 = ("a0000000-0000-0000-0000-000000000001", "a0000000-0000-0000-0000-000000000002",
              "a0000000-0000-0000-0000-000000000003")
G1 = "c0000000-0000-0000-0000-000000000001"
APP = "b0000000-0000-0000-0000-000000000001"
LOC = "e0000000-0000-0000-0000-000000000001"
DIRECTORY_READERS = "88d8e3e3-8f55-4a1e-953a-9b9898b8876b"
ADMIN_ROLES = ["62e90394-69f5-4237-9190-012177145e10", "194ae4cb-b126-40b2-bd5b-6091b380977d",
               "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9", "e8611ab8-c189-46e8-94e1-60213ab1f814",
               "c4e39bd9-1100-46d3-8c65-fb160da0071f", "7be44c8a-adaf-4e2a-84d6-ab2649e08a13"]


def _loaders(filename):
    def plain():
        spec = importlib.util.spec_from_file_location("row36b_" + filename[:-3], HERE / filename)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.transform

    def sandbox():
        spec = importlib.util.spec_from_file_location("row36b_sandbox", ROOT / "tools" / "restricted_sandbox.py")
        box = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(box)
        return box.load((HERE / filename).read_text(), "<transformation>")["transform"]

    out = [pytest.param(plain, id="plain")]
    try:
        import RestrictedPython  # noqa: F401
        out.append(pytest.param(sandbox, id="sandbox"))
    except ImportError:  # CI installs RestrictedPython from requirements-test.txt
        pass
    return out


@pytest.fixture(params=_loaders("ismfaenforcedforusers.py"), scope="module")
def mfa(request):
    return request.param()


@pytest.fixture(params=_loaders("legacyauthblocked.py"), scope="module")
def legacy(request):
    return request.param()


@pytest.fixture(params=_loaders("ismfaconfiguredforsecurityadmins.py"), scope="module")
def admins(request):
    return request.param()


def ca_policy(name="P", grant=("mfa",), include_users=("All",), include_groups=(), include_roles=(), apps=("All",),
              conditions=None, **users):
    u = {"includeUsers": list(include_users), "excludeUsers": [], "includeGroups": list(include_groups),
         "excludeGroups": [], "includeRoles": list(include_roles), "excludeRoles": []}
    u.update(users)
    c = {"users": u, "applications": {"includeApplications": list(apps), "excludeApplications": []},
         "clientAppTypes": ["all"], "userRiskLevels": [], "signInRiskLevels": []}
    c.update(conditions or {})
    return {"displayName": name, "state": "enabled", "conditions": c,
            "grantControls": {"operator": "OR", "builtInControls": list(grant)}}


def verdict(out, key):
    return out["transformedResponse"][key], out["additionalInfo"]["dataCollection"]["status"]


NARROWINGS = [
    pytest.param({}, (APP,), id="one-app"),
    pytest.param({"locations": {"includeLocations": [LOC], "excludeLocations": []}}, ("All",), id="named-location"),
    pytest.param({"platforms": {"includePlatforms": ["android"], "excludePlatforms": []}}, ("All",), id="platform"),
    pytest.param({"platforms": {"includePlatforms": ["all"], "excludePlatforms": ["iOS"]}}, ("All",),
                 id="platform-excluded"),
    pytest.param({"clientAppTypes": ["browser"]}, ("All",), id="client-type"),
    pytest.param({"devices": {"deviceFilter": {"mode": "include", "rule": "device.isCompliant -eq False"}}}, ("All",),
                 id="device-filter"),
]


# --- 1. isMFAEnforcedForUsers: a narrowed All-users policy is not all-users enforcement -------------------------------

MFA_KEY = "isMFAEnforcedForUsers"


def mfa_body(*policies):
    return {"authMethodsPolicy": {"authenticationMethodConfigurations": [{"id": "MicrosoftAuthenticator",
                                                                          "state": "enabled"}]},
            "conditionalAccessPolicies": {"value": list(policies)}}


@pytest.mark.parametrize("conditions,apps", NARROWINGS)
def test_mfa_narrowed_all_users_policy_does_not_count(mfa, conditions, apps):
    out = mfa(copy.deepcopy(mfa_body(ca_policy("Narrowed", apps=apps, conditions=conditions))))
    assert verdict(out, MFA_KEY) == (False, "success")
    assert "Narrowed" in " ".join(out["additionalInfo"]["evaluation"]["failReasons"])


@pytest.mark.parametrize("conditions,apps", NARROWINGS)
def test_mfa_narrowed_policy_next_to_a_whole_one_still_passes(mfa, conditions, apps):
    out = mfa(copy.deepcopy(mfa_body(ca_policy("Narrowed", apps=apps, conditions=conditions), ca_policy("Whole"))))
    assert verdict(out, MFA_KEY) == (True, "success")
    assert out["transformedResponse"]["policiesEnforcingMFAForUsers"] == ["Whole"]


@pytest.mark.parametrize("conditions", [
    {"locations": {"includeLocations": ["All"], "excludeLocations": ["AllTrusted"]}},
    {"platforms": {"includePlatforms": ["all"]}},
    {"clientAppTypes": ["browser", "mobileAppsAndDesktopClients"]},
    {"clientAppTypes": []},
])
def test_mfa_conditions_that_do_not_narrow_still_pass(mfa, conditions):
    assert verdict(mfa(copy.deepcopy(mfa_body(ca_policy(conditions=conditions)))), MFA_KEY) == (True, "success")


def test_mfa_narrowed_policy_next_to_a_group_policy_is_not_evaluated(mfa):
    group = ca_policy("Group", include_users=(), include_groups=(G1,))
    out = mfa(copy.deepcopy(mfa_body(ca_policy("Narrowed", apps=(APP,)), group)))
    assert verdict(out, MFA_KEY) == (None, "error")


# --- 2. legacyAuthBlocked: the block must reach all users ------------------------------------------------------------

LEGACY_KEY = "legacyAuthBlocked"


def block(name="Block legacy", **kw):
    p = ca_policy(name, grant=("block",), **kw)
    p["conditions"]["clientAppTypes"] = ["exchangeActiveSync", "other"]
    return p


def legacy_body(*policies):
    return {"value": list(policies)}


def test_legacy_block_for_named_users_only_fails(legacy):
    out = legacy(legacy_body(block(include_users=(U1,))))
    assert verdict(out, LEGACY_KEY) == (False, "success")
    assert "all users" in " ".join(out["additionalInfo"]["evaluation"]["failReasons"])


@pytest.mark.parametrize("kw", [
    pytest.param({"include_users": (), "include_groups": (G1,)}, id="group-scope"),
    pytest.param({"include_users": (), "include_roles": (ADMIN_ROLES[0],)}, id="role-scope"),
    # One excluded group is break-glass under row 36B (c): see test_36b_c_*.
    pytest.param({"excludeRoles": [DIRECTORY_READERS]}, id="excludes-role"),
    pytest.param({"excludeUsers": ["GuestsOrExternalUsers"]}, id="excludes-guests-keyword"),
    pytest.param({"excludeGuestsOrExternalUsers": {"guestOrExternalUserTypes": "b2bCollaborationGuest"}},
                 id="excludes-guests"),
    pytest.param({"excludeUsers": [U1, U2, U3]}, id="excludes-three-accounts"),
])
def test_legacy_block_whose_reach_is_unproven_is_not_evaluated(legacy, kw):
    out = legacy(legacy_body(block(**kw)))
    assert verdict(out, LEGACY_KEY) == (None, "error")
    assert out["additionalInfo"]["evaluation"]["failReasons"] == []


@pytest.mark.parametrize("excluded", [[], [U1], [U1, U2]])
def test_legacy_block_for_all_users_with_up_to_two_break_glass_accounts_passes(legacy, excluded):
    assert verdict(legacy(legacy_body(block(excludeUsers=excluded))), LEGACY_KEY) == (True, "success")


def test_legacy_excluded_group_covered_by_another_block_passes(legacy):
    out = legacy(legacy_body(block("All but G1", excludeGroups=[G1]),
                             block("G1", include_users=(), include_groups=(G1,))))
    assert verdict(out, LEGACY_KEY) == (True, "success")


def test_legacy_excluded_accounts_covered_by_another_block_do_not_count_towards_the_limit(legacy):
    out = legacy(legacy_body(block("All but three", excludeUsers=[U1, U2, U3]),
                             block("Three", include_users=(U1, U2, U3))))
    assert verdict(out, LEGACY_KEY) == (True, "success")


def test_legacy_no_blocking_policy_still_fails(legacy):
    assert verdict(legacy(legacy_body(ca_policy())), LEGACY_KEY) == (False, "success")


# --- 3. isMFAConfiguredForSecurityAdmins: aligned with the strict checks ----------------------------------------------

ADMIN_KEY = "isMFAConfiguredForSecurityAdmins"


def admin_policy(name="Admins", **kw):
    kw.setdefault("include_users", ())
    kw.setdefault("include_roles", tuple(ADMIN_ROLES))
    return ca_policy(name, **kw)


def test_admins_whole_policy_still_passes(admins):
    assert verdict(admins({"value": [admin_policy()]}), ADMIN_KEY) == (True, "success")


@pytest.mark.parametrize("conditions,apps", [n for n in NARROWINGS if n.id != "one-app"]
                         + [pytest.param({"locations": {"includeLocations": [LOC, "AllTrusted"]}}, ("All",),
                                         id="trusted-locations-only")])
def test_admins_narrowed_policy_does_not_count(admins, conditions, apps):
    out = admins({"value": [admin_policy(apps=apps, conditions=conditions)]})
    assert verdict(out, ADMIN_KEY) == (False, "success")
    assert "Admins" in " ".join(out["additionalInfo"]["evaluation"]["additionalFindings"])


@pytest.mark.parametrize("users", [
    # One excluded group is break-glass under row 36B (c): see test_36b_c_*.
    pytest.param({"excludeRoles": [DIRECTORY_READERS]}, id="excludes-role"),
    pytest.param({"excludeUsers": ["GuestsOrExternalUsers"]}, id="excludes-guests-keyword"),
    pytest.param({"excludeGuestsOrExternalUsers": {"guestOrExternalUserTypes": "b2bCollaborationGuest"}},
                 id="excludes-guests"),
    pytest.param({"excludeUsers": [U1, U2, U3]}, id="excludes-three-accounts"),
])
def test_admins_exclusions_beyond_break_glass_are_not_evaluated(admins, users):
    out = admins({"value": [admin_policy(**users)]})
    assert verdict(out, ADMIN_KEY) == (None, "error")
    assert "exclu" in " ".join(out["additionalInfo"]["dataCollection"]["errors"])


def test_admins_more_than_two_accounts_excluded_in_total_is_not_evaluated(admins):
    a = admin_policy("A", include_roles=tuple(ADMIN_ROLES[:3]), excludeUsers=[U1, U2])
    b = admin_policy("B", include_roles=tuple(ADMIN_ROLES[3:]), excludeUsers=[U3])
    assert verdict(admins({"value": [a, b]}), ADMIN_KEY) == (None, "error")


@pytest.mark.parametrize("excluded", [[U1], [U1, U2]])
def test_admins_up_to_two_break_glass_accounts_pass(admins, excluded):
    assert verdict(admins({"value": [admin_policy(excludeUsers=excluded)]}), ADMIN_KEY) == (True, "success")


@pytest.mark.parametrize("conditions", [
    {"locations": {"includeLocations": ["All"], "excludeLocations": ["AllTrusted"]}},
    {"applications": {"includeApplications": ["All"], "excludeApplications": [APP]}},
])
def test_admins_location_and_app_exclusions_stay_findings(admins, conditions):
    out = admins({"value": [admin_policy(conditions=conditions)]})
    assert verdict(out, ADMIN_KEY) == (True, "success")
    assert out["additionalInfo"]["evaluation"]["additionalFindings"]


def test_admins_a_proven_gap_still_fails_next_to_an_unproven_role(admins):
    unproven = admin_policy("Some", include_roles=tuple(ADMIN_ROLES[:5]), excludeGroups=[G1, G2])
    out = admins({"value": [unproven]})
    assert verdict(out, ADMIN_KEY) == (False, "success")


def test_mfa_all_users_policy_that_does_not_name_its_apps_is_not_evaluated(mfa):
    p = ca_policy("No apps")
    del p["conditions"]["applications"]
    out = mfa(copy.deepcopy(mfa_body(p)))
    assert verdict(out, MFA_KEY) == (None, "error")
    assert "does not say which apps" in " ".join(out["additionalInfo"]["dataCollection"]["errors"])


# --- 4. Row 36B (decision 18 Oct 2026) ---------------------------------------------------------------------------------
# (a) MFA for all users split across several narrowed All-users policies, none whole on its own: not evaluated (their
#     union is not judged), never Met and never Failed. Policies that are all scoped to some apps stay Failed: no
#     union of app lists reaches every app.
# (b) An All-users MFA policy that excludes apps leaves those apps without MFA: with nothing else counting, Failed.
# (c) Break-glass exclusions of at most 2 named accounts or 1 group (not both) are Met, and the reasons name them.
#     More than that (3 accounts, 2 groups, or a group and an account) is not Met.
# Trusted locations are unchanged (see the "do not narrow" and "stay findings" tests above).

G2 = "c0000000-0000-0000-0000-000000000002"
APP2 = "b0000000-0000-0000-0000-000000000002"


def ca_conditions(policy, **conditions):
    policy["conditions"].update(conditions)
    return policy


def excluding_apps(policy, apps):
    policy["conditions"]["applications"]["excludeApplications"] = list(apps)
    return policy


SPLITS = [
    pytest.param([ca_policy("Browser", conditions={"clientAppTypes": ["browser"]}),
                  ca_policy("Clients", conditions={"clientAppTypes": ["mobileAppsAndDesktopClients"]})],
                 id="client-types"),
    pytest.param([ca_policy("Mobile", conditions={"platforms": {"includePlatforms": ["android", "iOS"]}}),
                  ca_policy("Other platforms", conditions={"platforms": {"includePlatforms": ["all"],
                                                                         "excludePlatforms": ["android", "iOS"]}})],
                 id="platforms"),
    pytest.param([excluding_apps(ca_policy("All but one app"), [APP]), ca_policy("That app", apps=(APP,))],
                 id="apps"),
]


@pytest.mark.parametrize("policies", SPLITS)
def test_36b_a_mfa_split_across_several_policies_is_not_evaluated(mfa, policies):
    out = mfa(copy.deepcopy(mfa_body(*policies)))
    assert verdict(out, MFA_KEY) == (None, "error")
    errors = " ".join(out["additionalInfo"]["dataCollection"]["errors"])
    assert "split across 2 policies" in errors
    assert out["additionalInfo"]["evaluation"]["passReasons"] == []


@pytest.mark.parametrize("policies", SPLITS)
def test_36b_a_split_next_to_a_whole_policy_still_passes(mfa, policies):
    out = mfa(copy.deepcopy(mfa_body(*(policies + [ca_policy("Whole")]))))
    assert verdict(out, MFA_KEY) == (True, "success")
    assert out["transformedResponse"]["policiesEnforcingMFAForUsers"] == ["Whole"]


def test_36b_a_policies_that_are_all_app_scoped_stay_failed(mfa):
    out = mfa(copy.deepcopy(mfa_body(ca_policy("One app", apps=(APP,)), ca_policy("Another app", apps=(APP2,)))))
    assert verdict(out, MFA_KEY) == (False, "success")


def test_36b_a_split_policies_with_exclusions_beyond_break_glass_stay_not_evaluated(mfa):
    out = mfa(copy.deepcopy(mfa_body(ca_policy("Browser", conditions={"clientAppTypes": ["browser"]},
                                               excludeUsers=[U1, U2, U3]),
                                     ca_policy("Clients", conditions={"clientAppTypes": ["mobileAppsAndDesktopClients"]}))))
    assert verdict(out, MFA_KEY) == (None, "error")


@pytest.mark.parametrize("excluded", [[APP], [APP, APP2]])
def test_36b_b_mfa_policy_that_excludes_apps_fails(mfa, excluded):
    out = mfa(copy.deepcopy(mfa_body(excluding_apps(ca_policy("Excludes apps"), excluded))))
    assert verdict(out, MFA_KEY) == (False, "success")
    reasons = " ".join(out["additionalInfo"]["evaluation"]["failReasons"])
    assert "Excludes apps" in reasons and "excludes some apps" in reasons


def test_36b_b_app_exclusion_next_to_a_whole_policy_still_passes(mfa):
    out = mfa(copy.deepcopy(mfa_body(excluding_apps(ca_policy("Excludes apps"), [APP]), ca_policy("Whole"))))
    assert verdict(out, MFA_KEY) == (True, "success")


@pytest.mark.parametrize("users,named", [
    pytest.param({"excludeUsers": [U1]}, ["user:" + U1], id="one-account"),
    pytest.param({"excludeUsers": [U1, U2]}, ["user:" + U1, "user:" + U2], id="two-accounts"),
    pytest.param({"excludeGroups": [G1]}, ["group:" + G1], id="one-group"),
])
def test_36b_c_mfa_break_glass_exclusions_pass_and_are_named(mfa, users, named):
    out = mfa(copy.deepcopy(mfa_body(ca_policy("All users", **users))))
    assert verdict(out, MFA_KEY) == (True, "success")
    reasons = " ".join(out["additionalInfo"]["evaluation"]["passReasons"])
    for principal in named:
        assert principal in reasons


@pytest.mark.parametrize("policies", [
    pytest.param([ca_policy("All users", excludeUsers=[U1, U2, U3])], id="three-accounts"),
    pytest.param([ca_policy("All users", excludeGroups=[G1, G2])], id="two-groups"),
    pytest.param([ca_policy("All users", excludeGroups=[G1], excludeUsers=[U1])], id="group-and-account"),
    pytest.param([ca_policy("A", excludeGroups=[G1]), ca_policy("B", excludeGroups=[G2])], id="two-groups-in-total"),
])
def test_36b_c_mfa_exclusions_beyond_break_glass_are_not_met(mfa, policies):
    out = mfa(copy.deepcopy(mfa_body(*policies)))
    assert verdict(out, MFA_KEY) == (None, "error")


def test_36b_c_mfa_break_glass_group_with_trusted_locations_excluded_still_passes(mfa):
    p = ca_policy("All users", excludeGroups=[G1],
                  conditions={"locations": {"includeLocations": ["All"], "excludeLocations": ["AllTrusted"]}})
    assert verdict(mfa(copy.deepcopy(mfa_body(p))), MFA_KEY) == (True, "success")


@pytest.mark.parametrize("users,named", [
    pytest.param({"excludeUsers": [U1, U2]}, ["user:" + U1, "user:" + U2], id="two-accounts"),
    pytest.param({"excludeGroups": [G1]}, ["group:" + G1], id="one-group"),
])
def test_36b_c_legacy_break_glass_exclusions_pass_and_are_named(legacy, users, named):
    out = legacy(legacy_body(block(**users)))
    assert verdict(out, LEGACY_KEY) == (True, "success")
    reasons = " ".join(out["additionalInfo"]["evaluation"]["passReasons"])
    for principal in named:
        assert principal in reasons


@pytest.mark.parametrize("policies", [
    pytest.param([block(excludeGroups=[G1, G2])], id="two-groups"),
    pytest.param([block(excludeGroups=[G1], excludeUsers=[U1])], id="group-and-account"),
    pytest.param([block("A", excludeGroups=[G1]), block("B", excludeGroups=[G2])], id="different-groups"),
])
def test_36b_c_legacy_exclusions_beyond_break_glass_are_not_met(legacy, policies):
    assert verdict(legacy(legacy_body(*policies)), LEGACY_KEY) == (None, "error")


def test_36b_c_legacy_one_group_excluded_by_both_blocks_passes(legacy):
    out = legacy(legacy_body(block("A", excludeGroups=[G1]), block("B", excludeGroups=[G1])))
    assert verdict(out, LEGACY_KEY) == (True, "success")
    assert "group:" + G1 in " ".join(out["additionalInfo"]["evaluation"]["passReasons"])


@pytest.mark.parametrize("users,named", [
    pytest.param({"excludeUsers": [U1, U2]}, [U1, U2], id="two-accounts"),
    pytest.param({"excludeGroups": [G1]}, [G1], id="one-group"),
])
def test_36b_c_admins_break_glass_exclusions_pass_and_are_named(admins, users, named):
    out = admins({"value": [admin_policy(**users)]})
    assert verdict(out, ADMIN_KEY) == (True, "success")
    reasons = " ".join(out["additionalInfo"]["evaluation"]["passReasons"])
    assert "break-glass" in reasons
    for principal in named:
        assert principal in reasons


@pytest.mark.parametrize("policies", [
    pytest.param([admin_policy(excludeGroups=[G1, G2])], id="two-groups"),
    pytest.param([admin_policy(excludeGroups=[G1], excludeUsers=[U1])], id="group-and-account"),
    pytest.param([admin_policy("A", include_roles=tuple(ADMIN_ROLES[:3]), excludeGroups=[G1]),
                  admin_policy("B", include_roles=tuple(ADMIN_ROLES[3:]), excludeGroups=[G2])],
                 id="two-groups-in-total"),
    pytest.param([admin_policy("A", include_roles=tuple(ADMIN_ROLES[:3]), excludeGroups=[G1]),
                  admin_policy("B", include_roles=tuple(ADMIN_ROLES[3:]), excludeUsers=[U1])],
                 id="group-and-account-in-total"),
])
def test_36b_c_admins_exclusions_beyond_break_glass_are_not_met(admins, policies):
    assert verdict(admins({"value": policies}), ADMIN_KEY) == (None, "error")


def membership(members):
    """The merged group-membership reads for G1, read whole (synthetic member ids)."""
    return {"workforceUsers": {"value": [{"id": m, "accountEnabled": True, "userType": "Member"}
                                         for m in [U1, U2, U3]]},
            "caPolicyGroups": {"groupIds": [{"id": G1}]},
            "groupMembers": [{"value": [{"id": m} for m in members]}]}


@pytest.mark.parametrize("members,expected", [
    pytest.param([U1, U2], True, id="two-members-is-break-glass"),
    pytest.param([U1, U2, U3], None, id="three-members-is-not"),
])
def test_36b_c_mfa_excluded_group_read_with_more_than_two_members_is_not_break_glass(mfa, members, expected):
    body = mfa_body(ca_policy("All users", excludeGroups=[G1]))
    body.update(membership(members))
    assert verdict(mfa(copy.deepcopy(body)), MFA_KEY)[0] is expected


def test_36b_a_split_policies_that_all_exclude_the_same_app_fail(mfa):
    # Rule (b) wins: the app is excluded by every all-apps policy and included by none, so it has no MFA.
    out = mfa(copy.deepcopy(mfa_body(
        excluding_apps(ca_policy("Browser", conditions={"clientAppTypes": ["browser"]}), [APP]),
        excluding_apps(ca_policy("Clients", conditions={"clientAppTypes": ["mobileAppsAndDesktopClients"]}), [APP]))))
    assert verdict(out, MFA_KEY) == (False, "success")


def test_36b_c_legacy_different_groups_next_to_a_block_with_no_exclusion_pass(legacy):
    out = legacy(legacy_body(block("A", excludeGroups=[G1]), block("B", excludeGroups=[G2]), block("C")))
    assert verdict(out, LEGACY_KEY) == (True, "success")
