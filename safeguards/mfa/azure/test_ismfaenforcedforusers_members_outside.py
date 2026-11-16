"""mfa/azure/ismfaenforcedforusers.py: members outside every MFA policy read False (code owner ruling, 5 Oct 2026).

When group membership was read whole and some enabled Member accounts are in no group or user list of any enabled
Conditional Access policy requiring MFA, the key reads False and the fail reason gives the count. Reach is read
generously (narrowed policies still reach), so a False is never a guess. Security defaults or per-user MFA evidence,
when present, keep it from failing: they pass the key or keep it not evaluated. Synthetic environment only (public repo).
"""
import builtins as real_builtins
import copy
import importlib.util
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
SOURCE = (HERE / "ismfaenforcedforusers.py").read_text()
KEY = "isMFAEnforcedForUsers"
G1 = "d0000000-0000-0000-0000-000000000001"
G2 = "d0000000-0000-0000-0000-000000000002"
U = ["b0000000-0000-0000-0000-00000000000%d" % i for i in range(1, 9)]  # 8 enabled members


def load():
    spec = importlib.util.spec_from_file_location("ismfa_outside", HERE / "ismfaenforcedforusers.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


M = load()


def policy(name, include_users=(), include_groups=(G1,), apps=("All",), extra=None, grant=None, **users):
    u = {"includeUsers": list(include_users), "includeGroups": list(include_groups)}
    u.update(users)
    conditions = {"users": u, "applications": {"includeApplications": list(apps)}}
    conditions.update(extra or {})
    return {"displayName": name, "state": "enabled", "conditions": conditions,
            "grantControls": grant or {"operator": "OR", "builtInControls": ["mfa"]}}


def body(policies, groups, members, **extra):
    b = {"authMethodsPolicy": {"authenticationMethodConfigurations": [{"id": "MicrosoftAuthenticator", "state": "enabled"}]},
         "conditionalAccessPolicies": {"value": list(policies)},
         "workforceUsers": {"value": [{"id": i, "accountEnabled": True, "userType": "Member"} for i in U]},
         "caPolicyGroups": {"groupIds": [{"id": g} for g in groups]},
         "groupMembers": [{"value": [{"id": i} for i in m]} for m in members]}
    b.update(extra)
    return b


def per_user(states, **page_extra):
    p = {"value": [{"id": uid, "perUserMfaState": st} for uid, st in states.items()]}
    p.update(page_extra)
    return p


def run(b, module=M):
    out = module.transform(copy.deepcopy(b))
    return out["transformedResponse"][KEY], out


def fail_text(out):
    return " ".join(out["additionalInfo"]["evaluation"].get("failReasons") or [])


def error_text(out):
    return " ".join(out["additionalInfo"]["dataCollection"].get("errors") or [])


# --- the ruling: False with the count ------------------------------------------------------------------------------

def test_all_members_outside_fail():
    value, out = run(body([policy("VIP")], [G1], [[]]))
    assert value is False
    assert "8 of 8 enabled member accounts are not covered by any enabled Conditional Access policy that requires MFA" \
        in fail_text(out)
    assert out["transformedResponse"]["membersOutsideCount"] == 8


def test_some_members_outside_fail():
    value, out = run(body([policy("A")], [G1], [U[:5]]))
    assert value is False
    assert "3 of 8 enabled member accounts are not covered" in fail_text(out)


def test_one_member_outside_singular():
    value, out = run(body([policy("A")], [G1], [U[:7]]))
    assert value is False and "1 of 8 enabled member account is not covered" in fail_text(out)


def test_every_member_covered_still_passes():
    assert run(body([policy("A"), policy("B", include_groups=(G2,))], [G1, G2], [U[:4], U[4:]]))[0] is True


def test_risk_only_all_users_policy_does_not_reach():
    risky = policy("risk", include_users=("All",), include_groups=(), extra={"signInRiskLevels": ["high"]})
    value, out = run(body([policy("A"), risky], [G1], [U[:5]]))
    assert value is False and "3 of 8" in fail_text(out)


# --- security defaults and per-user MFA ----------------------------------------------------------------------------

def test_security_defaults_enabled_never_fails():
    value, out = run(body([policy("A")], [G1], [U[:5]], securityDefaults={"isEnabled": True}))
    assert value is None
    assert out["transformedResponse"]["membersOutsideUndecided"].startswith("security defaults are enabled")


@pytest.mark.parametrize("defaults", [{"error": {"code": "x"}}, {}, {"isEnabled": "maybe"}])
def test_security_defaults_not_read_never_fails(defaults):
    assert run(body([policy("A")], [G1], [U[:5]], securityDefaults=defaults))[0] is None


def test_security_defaults_read_off_still_fails():
    assert run(body([policy("A")], [G1], [U[:5]], securityDefaults={"isEnabled": "False"}))[0] is False


def test_per_user_mfa_covering_everyone_outside_passes():
    states = {U[5]: "enforced", U[6]: "enforced", U[7]: "enforced"}
    value, out = run(body([policy("A")], [G1], [U[:5]], perUserMfaStates=per_user(states)))
    assert value is True
    assert "per-user MFA covers the other 3" in " ".join(out["additionalInfo"]["evaluation"]["passReasons"])


def test_per_user_list_missing_an_outside_member_never_fails():
    states = {U[5]: "enforced", U[6]: "disabled"}  # U[7] has no entry
    value, out = run(body([policy("A")], [G1], [U[:5]], perUserMfaStates=per_user(states)))
    assert value is None
    assert out["transformedResponse"]["membersOutsideUndecided"].startswith(
        "the per-user MFA list does not show every member outside")


@pytest.mark.parametrize("flag", [{"itemErrors": [{"index": 1}]}, {"iterateTruncated": True}])
def test_per_user_fan_out_errors_never_fail(flag):
    states = {U[5]: "enforced", U[6]: "disabled", U[7]: "disabled"}
    b = body([policy("A")], [G1], [U[:5]], perUserMfaStates=per_user(states))
    b.update(flag)
    assert run(b)[0] is None


@pytest.mark.parametrize("item", [{}, {"perUserMfaState": None}, {"perUserMfaState": "unknown"}])
def test_per_user_entry_without_a_known_state_never_fails(item):
    p = per_user({U[5]: "enforced", U[6]: "disabled"})
    p["value"].append(dict({"id": U[7]}, **item))
    assert run(body([policy("A")], [G1], [U[:5]], perUserMfaStates=p))[0] is None


@pytest.mark.parametrize("extra", [{"@odata.nextLink": "https://graph.microsoft.com/v1.0/next"},
                                   {"paginationTruncated": True}, {"@odata.count": 9},
                                   {"vendorErrorAsResponse": {"status": 429}}])
def test_policy_list_not_read_whole_never_fails(extra):
    b = body([policy("A")], [G1], [U[:5]])
    b["conditionalAccessPolicies"].update(extra)
    value, out = run(b)
    assert value is None
    assert out["transformedResponse"]["membersOutsideUndecided"] == "the Conditional Access policy list was not read whole"


def test_bare_array_policy_list_never_fails():
    b = body([policy("A")], [G1], [U[:5]])
    b["conditionalAccessPolicies"] = b["conditionalAccessPolicies"]["value"]
    value, out = run(b)
    assert value is None
    assert out["transformedResponse"]["membersOutsideUndecided"] == "the Conditional Access policy list was not read whole"


def test_per_user_enabled_neither_covers_nor_fails():
    states = {U[5]: "enforced", U[6]: "enforced", U[7]: "enabled"}
    value, out = run(body([policy("A")], [G1], [U[:5]], perUserMfaStates=per_user(states)))
    assert value is None  # "enabled": MFA on modern sign-ins only, so neither True nor a False
    assert "enabled" in out["transformedResponse"]["membersOutsideUndecided"]


def test_per_user_mfa_covering_some_fails_on_the_rest():
    states = {U[5]: "enforced", U[6]: "disabled", U[7]: "disabled"}
    value, out = run(body([policy("A")], [G1], [U[:5]], perUserMfaStates=per_user(states)))
    assert value is False and "2 of 8 enabled member accounts are not covered" in fail_text(out)


@pytest.mark.parametrize("raw", [per_user({U[5]: "enforced"}, **{"@odata.nextLink": "https://graph.microsoft.com/n"}),
                                 {"error": {"code": "x"}}, {"value": [{"perUserMfaState": "enforced"}]}])
def test_per_user_list_not_read_whole_never_fails(raw):
    assert run(body([policy("A")], [G1], [U[:5]], perUserMfaStates=raw))[0] is None


# --- never a guess ------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("narrowed", [
    policy("loc", include_groups=(G2,), extra={"locations": {"includeLocations": ["x"]}}),
    policy("apps", include_groups=(G2,), apps=("00000003-0000-0ff1-ce00-000000000000",)),
    policy("or", include_groups=(G2,), grant={"operator": "OR", "builtInControls": ["mfa", "compliantDevice"]}),
    policy("exclgroup", include_groups=(G2,), excludeGroups=["d0000000-0000-0000-0000-000000000009"]),
    policy("guests", include_users=("All",), include_groups=(),
           excludeGuestsOrExternalUsers={"guestOrExternalUserTypes": "b2bCollaborationGuest"}),
])
def test_members_reached_by_a_narrowed_policy_stay_not_evaluated(narrowed):
    # The 3 members outside G1 are in G2 (or All), which a narrowed MFA policy includes: never a False.
    value, out = run(body([policy("A"), narrowed], [G1, G2], [U[:5], U[5:]]))
    assert value is None
    assert "3 of 8 enabled members are outside the included groups" in error_text(out)


def test_all_users_policy_excluding_a_read_group_leaves_that_group_outside():
    all_but = policy("All but G2", include_users=("All",), include_groups=(), excludeGroups=[G2])
    value, out = run(body([policy("A"), all_but], [G1, G2], [U[:2], U[1:4]]))
    assert value is False and "2 of 8" in fail_text(out)  # U[2], U[3]: excluded from All, not in G1


def test_role_including_policy_never_fails_without_the_role_read():
    admins = policy("admins", include_groups=(), includeRoles=["62e90394-69f5-4237-9190-012177145e10"])
    value, out = run(body([policy("A"), admins], [G1], [U[:5]]))
    assert value is None
    assert "directory role" in out["transformedResponse"]["membersOutsideUndecided"]


# --- WI-3a (product decision 16 Nov 2026): role holders, no group candidate, break-glass groups -------------------

GA = "62e90394-69f5-4237-9190-012177145e10"


def roles(*pairs, **page_extra):
    """pairs: (principal id, @odata.type suffix or None); every assignment is Global Administrator."""
    value = []
    for pid, kind in pairs:
        principal = {"id": pid}
        if kind:
            principal["@odata.type"] = "#microsoft.graph." + kind
        value.append({"roleDefinitionId": GA, "principalId": pid, "directoryScopeId": "/", "principal": principal})
    p = {"value": value}
    p.update(page_extra)
    return p


ADMINS = policy("admins", include_groups=(), includeRoles=[GA])


def test_real_shape_role_holders_read_lets_the_rule_fail():
    value, out = run(body([policy("A"), ADMINS], [G1], [U[:5]], roleAssignments=roles((U[5], "user"))))
    assert value is False
    assert "2 of 8 enabled member accounts are not covered" in fail_text(out)  # U[6], U[7]


def test_flipped_role_holders_cover_everyone_left():
    value, out = run(body([policy("A"), ADMINS], [G1], [U[:5]],
                          roleAssignments=roles((U[5], "user"), (U[6], None), (U[7], "user"))))
    assert value is None
    assert "membersOutsideCount" not in out["transformedResponse"]


def test_role_holders_wrapped_in_raw_response_are_read():
    # Azure AD's getDirectoryRoleAssignments returns {"apiResponse": ["rawResponse"]}.
    value, _ = run(body([policy("A"), ADMINS], [G1], [U[:5]],
                        roleAssignments={"rawResponse": roles((U[5], "user"))}))
    assert value is False


@pytest.mark.parametrize("role_body", [
    None, {}, {"stepError": True, "errorSummary": "the vendor returned HTTP 403"},
    {"error": {"code": "Authorization_RequestDenied"}}, roles((U[5], "user"), **{"@odata.nextLink": "https://x/n"}),
    roles((U[5], "user"), paginationTruncated=True), roles(("e0000000-0000-0000-0000-000000000001", "group")),
    roles(("e0000000-0000-0000-0000-000000000002", None)),
], ids=["none", "empty", "step-error", "graph-error", "paged", "truncated", "group-holder", "untyped-outsider"])
def test_role_read_that_is_not_whole_never_fails(role_body):
    value, out = run(body([policy("A"), ADMINS], [G1], [U[:5]], roleAssignments=role_body))
    assert value is None
    assert "directory role" in out["transformedResponse"]["membersOutsideUndecided"]


def test_service_principal_holder_is_not_a_member_and_does_not_block():
    value, _ = run(body([policy("A"), ADMINS], [G1], [U[:5]],
                        roleAssignments=roles(("e0000000-0000-0000-0000-000000000003", "servicePrincipal"))))
    assert value is False


def test_no_group_candidate_still_fails_members_outside_every_policy():
    # The only MFA policy targets All users from iOS only: it is narrowed (no group candidate), yet it reaches
    # everyone, so nobody is outside; add an excluded-by-name trio and they are.
    narrowed = policy("All iOS", include_users=("All",), include_groups=(),
                      extra={"platforms": {"includePlatforms": ["iOS"]}}, excludeUsers=U[5:8])
    value, out = run(body([narrowed], [], []))
    assert value is False
    assert "3 of 8 enabled member accounts are not covered" in fail_text(out)


READER = "4a5d8f65-41da-4de4-8968-e035b65339cf"  # an excluded role sets the policy aside but excludes nobody here


def test_no_group_candidate_with_everyone_reached_stays_unevaluated():
    aside = policy("All but readers", include_users=("All",), include_groups=(), excludeRoles=[READER])
    value, out = run(body([aside], [], []))
    assert value is None
    assert "no set-aside policy is one it can decide" in error_text(out)


def test_no_group_candidate_with_role_unread_names_why():
    narrowed = policy("All iOS", include_users=("All",), include_groups=(),
                      extra={"platforms": {"includePlatforms": ["iOS"]}}, excludeUsers=U[5:8])
    value, out = run(body([narrowed, ADMINS], [], []))
    assert value is None
    assert "members outside cannot be counted: an MFA policy includes a directory role" in error_text(out)


@pytest.mark.parametrize("group_members,expected", [
    ([U[7]], None),           # one-account excluded group: break-glass, nothing fails
    (U[5:8], False),          # three accounts: not break-glass, all three outside every policy
])
def test_excluded_group_is_break_glass_only_when_small(group_members, expected):
    all_but = policy("All but G2", include_users=("All",), include_groups=(), excludeGroups=[G2],
                     excludeRoles=[READER])
    value, _ = run(body([all_but], [G2], [group_members]))
    assert value is expected


# --- authentication strengths (grantControls.authenticationStrength, builtInControls empty) -----------------------

STRENGTH_MFA = "00000000-0000-0000-0000-000000000002"
STRENGTH_PHISHING_RESISTANT = "00000000-0000-0000-0000-000000000004"


def strength(name, strength_id, **kw):
    return policy(name, grant={"operator": "OR", "builtInControls": [],
                               "authenticationStrength": {"id": strength_id, "requirementsSatisfied": "mfa"}}, **kw)


@pytest.mark.parametrize("strength_id", [STRENGTH_MFA, STRENGTH_PHISHING_RESISTANT])
def test_strength_policy_covers_its_included_users(strength_id):
    # The 3 members outside G1 are in G2, which a strength-based policy includes: nobody is outside, no False.
    value, out = run(body([policy("A"), strength("S", strength_id, include_groups=(G2,))], [G1, G2], [U[:5], U[5:]]))
    assert value is not False
    assert "membersOutsideCount" not in out["transformedResponse"]


@pytest.mark.parametrize("strength_id", [STRENGTH_MFA, STRENGTH_PHISHING_RESISTANT])
def test_strength_policy_on_all_users_reaches_everyone(strength_id):
    all_users = strength("S all", strength_id, include_users=("All",), include_groups=(),
                         excludeGuestsOrExternalUsers={"guestOrExternalUserTypes": "b2bCollaborationGuest"})
    value, out = run(body([policy("A"), all_users], [G1], [U[:5]]))
    assert value is None
    assert "membersOutsideCount" not in out["transformedResponse"]


def test_strength_policy_leaves_its_non_members_outside():
    value, out = run(body([policy("A"), strength("S", STRENGTH_PHISHING_RESISTANT, include_groups=(G2,))],
                          [G1, G2], [U[:4], U[4:6]]))
    assert value is False and "2 of 8 enabled member accounts are not covered" in fail_text(out)


def test_unread_group_in_another_policy_never_fails():
    other = policy("B", include_groups=(G2,), extra={"locations": {"includeLocations": ["x"]}})
    b = body([policy("A"), other], [G1, G2], [U[:5], U[5:]])
    b["groupMembers"][1] = {"value": [{"id": U[5]}], "@odata.nextLink": "https://graph.microsoft.com/n"}
    assert run(b)[0] is None


def test_two_break_glass_accounts_outside_do_not_fail_three_do():
    two = policy("A", include_groups=(G1,), excludeUsers=U[6:8])
    assert run(body([two], [G1], [U[:6]]))[0] is True
    three = policy("A", include_groups=(G1,), excludeUsers=U[5:8])
    assert run(body([three, policy("B", include_groups=(G2,))], [G1, G2], [U[:5], []]))[0] is not True


def test_refused_or_unread_reads_never_fail():
    b = body([policy("A")], [G1], [U[:5]])
    b["groupMembers"] = [{"vendorErrorAsResponse": {"status": 403, "bodyContains": "Authorization_RequestDenied"}}]
    assert run(b)[0] is None
    b = body([policy("A")], [G1], [U[:5]])
    b["workforceUsers"]["@odata.nextLink"] = "https://graph.microsoft.com/n"
    assert run(b)[0] is None


def test_no_membership_keys_unchanged():
    b = body([policy("A")], [G1], [U[:5]])
    for key in ("workforceUsers", "caPolicyGroups", "groupMembers"):
        b.pop(key)
    value, out = run(b)
    assert value is None and "group membership is not read" in error_text(out)


def test_restricted_python_agrees_on_the_new_verdicts():
    pytest.importorskip("RestrictedPython")
    from RestrictedPython import compile_restricted, limited_builtins, safe_globals, utility_builtins
    from RestrictedPython.Eval import default_guarded_getitem, default_guarded_getiter
    from RestrictedPython.Guards import guarded_iter_unpack_sequence, guarded_unpack_sequence, safer_getattr
    for banned in ("getattr(", "re.compile", "strptime"):
        assert banned not in SOURCE
    code = compile_restricted(SOURCE, "<ismfaenforcedforusers>", "exec")

    def guarded_import(name, *args, **kwargs):
        if name not in {"json", "datetime", "warnings"}:
            raise ImportError(name)
        return real_builtins.__import__(name, *args, **kwargs)

    names = dict(safe_globals["__builtins__"])
    names.update(limited_builtins)
    names.update(utility_builtins)
    names.update(__import__=guarded_import, isinstance=isinstance, list=list, dict=dict, str=str, any=any,
                 all=all, bytes=bytes, set=set, sorted=sorted, len=len, min=min, max=max, int=int, bool=bool,
                 ValueError=ValueError, Exception=Exception, enumerate=enumerate, tuple=tuple)
    glb = dict(safe_globals)
    glb.update(__builtins__=names, _getitem_=default_guarded_getitem, _getiter_=default_guarded_getiter,
               _iter_unpack_sequence_=guarded_iter_unpack_sequence, _unpack_sequence_=guarded_unpack_sequence,
               _getattr_=safer_getattr, _write_=lambda x: x, __name__="sandboxed", __metaclass__=type)
    exec(code, glb)
    for b in (body([policy("A")], [G1], [[]]), body([policy("A")], [G1], [U[:5]]),
              body([policy("A")], [G1], [U[:5]], perUserMfaStates=per_user({U[5]: "enforced", U[6]: "enforced",
                                                                            U[7]: "enforced"})),
              body([policy("A"), strength("S", STRENGTH_PHISHING_RESISTANT, include_groups=(G2,))], [G1, G2],
                   [U[:4], U[4:6]]),
              body([policy("A")], [G1], [U[:5]], securityDefaults={"isEnabled": True})):
        s_out = glb["transform"](copy.deepcopy(b))
        p_out = M.transform(copy.deepcopy(b))
        assert s_out["transformedResponse"] == p_out["transformedResponse"]
        assert s_out["additionalInfo"]["evaluation"] == p_out["additionalInfo"]["evaluation"]
