"""mfa/azure/ismfaenforcedforusers.py: EXCLUDE_RISK_CONDITIONED and ALL_USERS_TARGET_MODE (4 Oct 2026).

Both default to False (today's behaviour). Each is tested off and on, alone and together, plain and under
RestrictedPython. Synthetic estate only.
"""
import builtins as real_builtins
import copy
import importlib.util
import json
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
SOURCE = (HERE / "ismfaenforcedforusers.py").read_text()
KEY = "isMFAEnforcedForUsers"
G1 = "c0000000-0000-0000-0000-000000000001"


def load(**switches):
    spec = importlib.util.spec_from_file_location("ismfa_switches", HERE / "ismfaenforcedforusers.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    # Baseline: both off (the pre-switch behaviour); each test sets what it exercises.
    module.EXCLUDE_RISK_CONDITIONED = False
    module.ALL_USERS_TARGET_MODE = "off"
    for name, value in switches.items():
        setattr(module, name, value)
    return module


def methods():
    return {"authenticationMethodConfigurations": [{"id": "MicrosoftAuthenticator", "state": "enabled"},
                                                   {"id": "Sms", "state": "enabled"}]}


def policy(name, include_users=("All",), include_groups=(), sign_in_risk=None, user_risk=None, **users):
    u = {"includeUsers": list(include_users), "includeGroups": list(include_groups)}
    u.update(users)
    conditions = {"users": u, "applications": {"includeApplications": ["All"]}}
    if sign_in_risk is not None:
        conditions["signInRiskLevels"] = sign_in_risk
    if user_risk is not None:
        conditions["userRiskLevels"] = user_risk
    return {"displayName": name, "state": "enabled", "conditions": conditions,
            "grantControls": {"operator": "OR", "builtInControls": ["mfa"]}}


def body(*policies):
    return {"authMethodsPolicy": methods(), "conditionalAccessPolicies": {"value": list(policies)}}


RISKY = policy("Microsoft-managed: risky sign-ins", sign_in_risk=["high"])
USER_RISK = policy("Password change for high-risk users", user_risk=["high"])
GROUP = policy("MFA pilot group", include_users=(), include_groups=(G1,))
ALL = policy("MFA all users")


def run(module, b):
    out = module.transform(copy.deepcopy(b))
    out["additionalInfo"]["metadata"].pop("evaluatedAt", None)
    return out


def test_shipped_values_are_jj_decision_of_4_oct():
    # J.J. chose (a) + (b-unevaluated) on 4 Oct 2026.
    spec = importlib.util.spec_from_file_location("ismfa_shipped", HERE / "ismfaenforcedforusers.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.EXCLUDE_RISK_CONDITIONED is True and module.ALL_USERS_TARGET_MODE == "unevaluated"


@pytest.mark.parametrize("p", [RISKY, USER_RISK, GROUP, ALL])
def test_switches_off_count_every_mfa_policy_as_before(p):
    out = run(load(), body(p))
    assert out["transformedResponse"][KEY] is True
    assert "policiesSetAside" not in out["transformedResponse"]


def test_switches_off_output_is_identical_to_explicit_false():
    for b in (body(RISKY), body(GROUP, ALL), body()):
        assert json.dumps(run(load(), b), sort_keys=True) == json.dumps(
            run(load(EXCLUDE_RISK_CONDITIONED=False, ALL_USERS_TARGET_MODE="off"), b), sort_keys=True)


def test_exclude_risk_on_sets_risk_policies_aside():
    m = load(EXCLUDE_RISK_CONDITIONED=True)
    out = run(m, body(RISKY, USER_RISK))
    assert out["transformedResponse"][KEY] is False
    reason = out["additionalInfo"]["evaluation"]["failReasons"][-1]
    assert '"Microsoft-managed: risky sign-ins" (fires only on sign-in or user risk)' in reason
    assert '"Password change for high-risk users" (fires only on sign-in or user risk)' in reason
    # A non-risk policy still counts; group policies are untouched by this switch.
    assert run(m, body(RISKY, GROUP))["transformedResponse"][KEY] is True
    # An empty risk list is not a risk condition.
    assert run(m, body(policy("x", sign_in_risk=[])))["transformedResponse"][KEY] is True


def test_require_all_users_on_sets_group_policies_aside():
    m = load(ALL_USERS_TARGET_MODE="not_met")
    out = run(m, body(GROUP))
    assert out["transformedResponse"][KEY] is False
    assert '"MFA pilot group" (targets groups, not all users)' in out["additionalInfo"]["evaluation"]["failReasons"][-1]
    assert run(m, body(GROUP, ALL))["transformedResponse"][KEY] is True
    # Risk policies still count unless the other switch is on.
    assert run(m, body(RISKY))["transformedResponse"][KEY] is True


@pytest.mark.parametrize("users,expect", [
    ({"excludeUsers": ["b0000000-0000-0000-0000-000000000001", "b0000000-0000-0000-0000-000000000002"]}, True),
    ({"excludeUsers": ["b0000000-0000-0000-0000-00000000000" + str(i) for i in range(3)]}, False),
    ({"excludeGroups": [G1]}, False),
    ({"excludeRoles": ["d0000000-0000-0000-0000-000000000001"]}, False),
    ({"excludeGuestsOrExternalUsers": {"guestOrExternalUserTypes": "b2bCollaborationGuest"}}, False),
    ({"excludeUsers": ["GuestsOrExternalUsers"]}, False),
    ({"excludeUsers": "not a list"}, False),
])
def test_all_users_exclusions_follow_the_coverage_convention(users, expect):
    out = run(load(ALL_USERS_TARGET_MODE="not_met"), body(policy("MFA all users", **users)))
    assert out["transformedResponse"][KEY] is expect
    if not expect:
        assert '"MFA all users" (excludes ' in out["additionalInfo"]["evaluation"]["failReasons"][-1]


def test_both_on_and_reason_is_capped_with_truncated_names():
    m = load(EXCLUDE_RISK_CONDITIONED=True, ALL_USERS_TARGET_MODE="not_met")
    many = [policy("G" * 100 + str(i), include_users=(), include_groups=(G1,)) for i in range(6)] + [RISKY]
    out = run(m, body(*many))
    assert out["transformedResponse"][KEY] is False
    reason = out["additionalInfo"]["evaluation"]["failReasons"][-1]
    assert reason.count('" (') == 5 and reason.endswith("and 2 more")
    assert ("G" * 77 + "...") in reason
    aside = out["transformedResponse"]["policiesSetAside"]
    assert len(aside) == 7 and all(len(a.split(" (")[0]) <= 80 for a in aside)
    assert run(m, body(*many, ALL))["transformedResponse"][KEY] is True


def test_switches_never_rescue_unread_or_external_inputs():
    m = load(EXCLUDE_RISK_CONDITIONED=True, ALL_USERS_TARGET_MODE="not_met")
    assert m.transform({"authMethodsPolicy": methods()})["transformedResponse"][KEY] is None
    assert m.transform({"error": {"code": "Forbidden"}})["transformedResponse"][KEY] is None


@pytest.mark.parametrize("switches", [{}, {"EXCLUDE_RISK_CONDITIONED": True}, {"ALL_USERS_TARGET_MODE": "not_met"},
                                      {"ALL_USERS_TARGET_MODE": "unevaluated"},
                                      {"EXCLUDE_RISK_CONDITIONED": True, "ALL_USERS_TARGET_MODE": "not_met"},
                                      {"EXCLUDE_RISK_CONDITIONED": True, "ALL_USERS_TARGET_MODE": "unevaluated"}])
def test_restricted_python_executes_and_agrees(switches):
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
    glb.update(EXCLUDE_RISK_CONDITIONED=False, ALL_USERS_TARGET_MODE="off")
    glb.update(switches)
    plain = load(**switches)
    for b in (body(RISKY), body(GROUP), body(ALL, RISKY), body(policy("x", excludeGroups=[G1])),
              body(*[policy("G" * 90 + str(i), include_users=(), include_groups=(G1,)) for i in range(7)])):
        s_out = glb["transform"](copy.deepcopy(b))
        p_out = plain.transform(copy.deepcopy(b))
        assert s_out["transformedResponse"] == p_out["transformedResponse"]
        assert s_out["additionalInfo"]["evaluation"] == p_out["additionalInfo"]["evaluation"]


# --- ALL_USERS_TARGET_MODE = "unevaluated" ---------------------------------------------------------------------------

def test_unevaluated_mode_reads_group_only_coverage_as_not_evaluated():
    m = load(ALL_USERS_TARGET_MODE="unevaluated")
    out = run(m, body(GROUP))
    assert out["transformedResponse"][KEY] is None
    err = out["additionalInfo"]["dataCollection"]["errors"][0]
    assert err.startswith('MFA is required only by policies scoped to groups or with exclusions ("MFA pilot group")')
    assert "group membership is not read, so coverage of all users cannot be confirmed" in err
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"


def test_unevaluated_mode_all_users_with_excluded_group_is_not_evaluated():
    out = run(load(ALL_USERS_TARGET_MODE="unevaluated"), body(policy("MFA all users", excludeGroups=[G1])))
    assert out["transformedResponse"][KEY] is None


def test_unevaluated_mode_still_passes_and_fails_where_it_can():
    m = load(ALL_USERS_TARGET_MODE="unevaluated")
    assert run(m, body(GROUP, ALL))["transformedResponse"][KEY] is True
    # No MFA policy at all: still Not met (nothing was set aside).
    assert run(m, body())["transformedResponse"][KEY] is False
    # No MFA method enabled: still Not met, whatever the policies.
    b = body(GROUP)
    b["authMethodsPolicy"] = {"authenticationMethodConfigurations": [{"id": "Sms", "state": "enabled"}]}
    assert run(m, b)["transformedResponse"][KEY] is False


def test_unevaluated_mode_names_are_capped():
    many = [policy("G" * 100 + str(i), include_users=(), include_groups=(G1,)) for i in range(7)]
    err = run(load(ALL_USERS_TARGET_MODE="unevaluated"), body(*many))["additionalInfo"]["dataCollection"]["errors"][0]
    assert "and 2 more" in err and ("G" * 77 + "...") in err


def test_risk_switch_is_independent_of_the_target_mode():
    # Risk-only set-asides never make the key not evaluated; they make it Not met.
    m = load(EXCLUDE_RISK_CONDITIONED=True, ALL_USERS_TARGET_MODE="unevaluated")
    assert run(m, body(RISKY))["transformedResponse"][KEY] is False
    assert run(m, body(RISKY, GROUP))["transformedResponse"][KEY] is None
    assert run(load(ALL_USERS_TARGET_MODE="unevaluated"), body(RISKY))["transformedResponse"][KEY] is True


@pytest.mark.parametrize("mode", ["off", "unevaluated", "not_met"])
def test_unknown_inputs_stay_not_evaluated_in_every_mode(mode):
    m = load(ALL_USERS_TARGET_MODE=mode, EXCLUDE_RISK_CONDITIONED=True)
    assert m.transform({"authMethodsPolicy": methods()})["transformedResponse"][KEY] is None


# --- ALL_USERS_TARGET_MODE = "membership" ----------------------------------------------------------------------------
U1, U2, U3 = ("b0000000-0000-0000-0000-00000000000" + str(i) for i in (1, 2, 3))
G2 = "c0000000-0000-0000-0000-000000000002"


def workforce(*ids, extra=()):
    value = [{"id": i, "accountEnabled": True, "userType": "Member", "displayName": "User " + i[-1]} for i in ids]
    value += list(extra)
    return {"@odata.count": len(value), "value": value}


def members(*ids):
    return {"@odata.count": len(ids), "value": [{"@odata.type": "#microsoft.graph.user", "id": i} for i in ids]}


def with_membership(b, wf, groups):
    b = copy.deepcopy(b)
    b["workforceUsers"] = wf
    b["caPolicyGroups"] = {"groupIds": [{"id": g} for g, _ in groups]}
    b["groupMembers"] = [m for _, m in groups]
    return b


MEM = dict(ALL_USERS_TARGET_MODE="membership")


def test_membership_covers_every_member_reads_met():
    out = run(load(**MEM), with_membership(body(GROUP), workforce(U1, U2), [(G1, members(U1, U2))]))
    assert out["transformedResponse"][KEY] is True
    assert out["transformedResponse"]["membersOutsideGroups"] == 0
    assert "group membership read" in out["additionalInfo"]["evaluation"]["passReasons"][-1]


def test_membership_ignores_guests_and_disabled_accounts():
    extra = ({"id": U3, "accountEnabled": False, "userType": "Member"},
             {"id": "b0000000-0000-0000-0000-0000000000f1", "accountEnabled": True, "userType": "Guest"})
    out = run(load(**MEM), with_membership(body(GROUP), workforce(U1, extra=extra), [(G1, members(U1))]))
    assert out["transformedResponse"][KEY] is True


def test_members_outside_read_not_met_and_are_named_capped():
    ids = ["b1000000-0000-0000-0000-0000000000" + str(10 + i) for i in range(25)]
    out = run(load(**MEM), with_membership(body(GROUP), workforce(U1, *ids), [(G1, members(U1))]))
    assert out["transformedResponse"][KEY] is False
    reason = out["additionalInfo"]["evaluation"]["failReasons"][0]
    assert reason.startswith("25 of 26 enabled member accounts are outside every group")
    assert reason.endswith("and 5 more")


def test_up_to_two_named_exclusions_are_allowed():
    p = policy("MFA pilot group", include_users=(), include_groups=(G1,), excludeUsers=[U2])
    out = run(load(**MEM), with_membership(body(p), workforce(U1, U2), [(G1, members(U1))]))
    assert out["transformedResponse"][KEY] is True


def test_outside_members_with_an_unresolved_policy_stay_not_evaluated():
    other = policy("MFA all users", excludeGroups=[G2])
    out = run(load(**MEM), with_membership(body(GROUP, other), workforce(U1, U2), [(G1, members(U1)), (G2, members())]))
    assert out["transformedResponse"][KEY] is None


@pytest.mark.parametrize("damage", ["no_reads", "next_link", "count_mismatch", "member_error", "unpaired",
                                    "item_errors", "truncated", "string_flag", "duplicate_group"])
def test_any_unreadable_membership_falls_back_to_unevaluated(damage):
    b = with_membership(body(GROUP), workforce(U1, U2), [(G1, members(U1, U2))])
    if damage == "no_reads":
        b = body(GROUP)
    elif damage == "next_link":
        b["workforceUsers"]["@odata.nextLink"] = "https://graph.microsoft.com/v1.0/users?$skiptoken=x"
    elif damage == "count_mismatch":
        b["groupMembers"][0]["@odata.count"] = 5
    elif damage == "member_error":
        b["groupMembers"][0] = {"vendorErrorAsResponse": {"status": 403}}
    elif damage == "unpaired":
        b["groupMembers"].append(members())
    elif damage == "item_errors":
        b["itemErrors"] = 1
    elif damage == "truncated":
        b["workforceUsers"]["paginationTruncated"] = True
    elif damage == "string_flag":
        b["workforceUsers"]["value"][0]["accountEnabled"] = "True"
    elif damage == "duplicate_group":
        b["caPolicyGroups"]["groupIds"].append({"id": G1})
        b["groupMembers"].append(members(U1))
    out = run(load(**MEM), b)
    assert out["transformedResponse"][KEY] is None
    assert "group membership is not read" in out["additionalInfo"]["dataCollection"]["errors"][0]


def test_membership_mode_without_reads_equals_unevaluated_mode():
    for b in (body(GROUP), body(GROUP, ALL), body(RISKY, GROUP), body(), body(policy("x", excludeGroups=[G1]))):
        assert json.dumps(run(load(**MEM), b), sort_keys=True) == json.dumps(
            run(load(ALL_USERS_TARGET_MODE="unevaluated"), b), sort_keys=True)


def test_membership_restricted_python_agrees():
    pytest.importorskip("RestrictedPython")
    from RestrictedPython import compile_restricted, limited_builtins, safe_globals, utility_builtins
    from RestrictedPython.Eval import default_guarded_getitem, default_guarded_getiter
    from RestrictedPython.Guards import guarded_iter_unpack_sequence, guarded_unpack_sequence, safer_getattr
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
    glb.update(MEM)
    plain = load(**MEM)
    ids = ["b1000000-0000-0000-0000-0000000000" + str(10 + i) for i in range(25)]
    for b in (with_membership(body(GROUP), workforce(U1, U2), [(G1, members(U1, U2))]),
              with_membership(body(GROUP), workforce(U1, *ids), [(G1, members(U1))]),
              with_membership(body(GROUP), workforce(U1), [(G1, {"vendorErrorAsResponse": {}})]), body(GROUP)):
        s_out = glb["transform"](copy.deepcopy(b))
        p_out = plain.transform(copy.deepcopy(b))
        assert s_out["transformedResponse"] == p_out["transformedResponse"]
        assert s_out["additionalInfo"]["evaluation"] == p_out["additionalInfo"]["evaluation"]
        assert s_out["additionalInfo"]["dataCollection"] == p_out["additionalInfo"]["dataCollection"]
