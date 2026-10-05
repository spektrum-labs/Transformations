"""mfa/azure/ismfaenforcedforusers.py: group-scoped MFA policies judged from the group-membership reads.

Rule (5 Oct 2026): group math can turn "not evaluated" into True. It turns it into False only when membership was read
whole and some enabled members are reached by no enabled MFA policy (code owner ruling, 5 Oct; see
test_ismfaenforcedforusers_members_outside.py). With no membership keys in the input the output is identical to the
shipped behaviour. Synthetic estate only (public repo).
"""
import builtins as real_builtins
import copy
import importlib.util
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
SOURCE = (HERE / "ismfaenforcedforusers.py").read_text()
KEY = "isMFAEnforcedForUsers"
G1 = "c0000000-0000-0000-0000-000000000001"
G2 = "c0000000-0000-0000-0000-000000000002"
U = ["a0000000-0000-0000-0000-00000000000%d" % i for i in range(1, 7)]


def load():
    spec = importlib.util.spec_from_file_location("ismfa_groups", HERE / "ismfaenforcedforusers.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


M = load()


def methods():
    return {"authenticationMethodConfigurations": [{"id": "MicrosoftAuthenticator", "state": "enabled"}]}


def policy(name, include_users=(), include_groups=(G1,), apps=("All",), extra_conditions=None, grant=None, **users):
    u = {"includeUsers": list(include_users), "includeGroups": list(include_groups)}
    u.update(users)
    conditions = {"users": u, "applications": {"includeApplications": list(apps)}}
    conditions.update(extra_conditions or {})
    return {"displayName": name, "state": "enabled", "conditions": conditions,
            "grantControls": grant or {"operator": "OR", "builtInControls": ["mfa"]}}


def page(ids, **extra):
    p = {"value": [{"id": i} for i in ids]}
    p.update(extra)
    return p


def workforce(ids, extra_items=()):
    return {"value": [{"id": i, "accountEnabled": True, "userType": "Member"} for i in ids] + list(extra_items)}


def body(policies, members=None, users=None, groups=None, raw_members=None):
    b = {"authMethodsPolicy": methods(), "conditionalAccessPolicies": {"value": list(policies)}}
    if members is not None or raw_members is not None:
        gids = groups if groups is not None else [G1, G2][:len(raw_members if raw_members is not None else members)]
        b["workforceUsers"] = workforce(users if users is not None else U)
        b["caPolicyGroups"] = {"groupIds": [{"id": g} for g in gids]}
        b["groupMembers"] = raw_members if raw_members is not None else [page(m) for m in members]
    return b


def run(b, module=M):
    out = module.transform(copy.deepcopy(b))
    return out["transformedResponse"][KEY], out


def reason(out):
    return " ".join(out["additionalInfo"]["dataCollection"]["errors"])


# --- unchanged without membership -----------------------------------------------------------------------------------

@pytest.mark.parametrize("policies", [[policy("G")], [policy("All", include_users=("All",), include_groups=())],
                                      [policy("x", include_users=("All",), include_groups=(), excludeGroups=[G1])],
                                      []])
def test_no_membership_keys_output_identical_to_shipped(policies):
    value, out = run(body(policies))
    assert "groupCoverage" not in out["transformedResponse"]
    if policies and policies[0]["conditions"]["users"]["includeGroups"] and not policies[0]["conditions"]["users"]["includeUsers"]:
        assert value is None and "group membership is not read, so coverage" in reason(out)


# --- True when the groups reach every enabled member ----------------------------------------------------------------

def test_groups_cover_every_member_pass():
    value, out = run(body([policy("A", include_groups=(G1,)), policy("B", include_groups=(G2,))],
                          members=[U[:3], U[3:]]))
    assert value is True
    assert out["transformedResponse"]["groupCoverage"]["membersTotal"] == 6
    assert "all 6 enabled member accounts are covered" in out["additionalInfo"]["evaluation"]["passReasons"][1]


def test_two_named_exclusions_allowed_three_not():
    ok, _ = run(body([policy("A", excludeUsers=U[4:6])], members=[U[:4]], groups=[G1]))
    assert ok is True
    no, _ = run(body([policy("A", excludeUsers=U[3:6])], members=[U[:3]], groups=[G1]))
    assert no is None  # more than 2 named exclusions: the policy is not a candidate
    spread, out = run(body([policy("A", include_groups=(G1,), excludeUsers=U[4:6]),
                            policy("B", include_groups=(G2,), excludeUsers=U[2:4])], members=[U[:4], U[:2]]))
    assert spread is None and "more than 2" in reason(out)  # 4 in total across the counting policies
    # U[4:6] are in no included group either; the two left outside are break-glass by name, so nothing fails


def test_guests_and_disabled_accounts_do_not_count():
    extra = [{"id": "b1", "accountEnabled": False, "userType": "Member"},
             {"id": "b2", "accountEnabled": True, "userType": "Guest"}]
    b = body([policy("A")], members=[U], groups=[G1])
    b["workforceUsers"] = workforce(U, extra)
    assert run(b)[0] is True


# --- members outside: False with the count (full rule in test_ismfaenforcedforusers_members_outside.py) ----------

def test_members_outside_fail_with_counts():
    value, out = run(body([policy("A")], members=[U[:2]], groups=[G1]))
    assert value is False
    assert "4 of 6 enabled member accounts are not covered" in " ".join(out["additionalInfo"]["evaluation"]["failReasons"])


@pytest.mark.parametrize("raw", [
    [{"vendorErrorAsResponse": {"status": 403, "bodyContains": "Authorization_RequestDenied", "body": {}}}],
    [{"error": {"code": "x"}}],
    [page(U, **{"@odata.nextLink": "https://graph.microsoft.com/next"})],
    [page(U, paginationTruncated=True)],
    [page(U, **{"@odata.count": 99})],
    [{"value": [{"displayName": "no id"}]}],
    [],
])
def test_unread_member_lists_never_pass_or_fail(raw):
    value, out = run(body([policy("A")], raw_members=raw, groups=[G1]))
    assert value is None


def test_refused_group_read_names_the_permission():
    raw = [{"vendorErrorAsResponse": {"status": 403, "bodyContains": "Authorization_RequestDenied", "body": {}}}]
    _, out = run(body([policy("A")], raw_members=raw, groups=[G1]))
    assert "GroupMember.Read.All" in reason(out)


def test_workforce_not_read_whole_stays_not_evaluated():
    b = body([policy("A")], members=[U], groups=[G1])
    b["workforceUsers"]["@odata.nextLink"] = "https://graph.microsoft.com/next"
    assert run(b)[0] is None
    b["workforceUsers"] = {"vendorErrorAsResponse": {"status": 403}}
    assert run(b)[0] is None


def test_duplicate_group_or_item_errors_pair_nothing():
    assert run(body([policy("A")], members=[U, U], groups=[G1, G1]))[0] is None
    b = body([policy("A")], members=[U], groups=[G1])
    b["itemErrors"] = [{"index": 0}]
    assert run(b)[0] is None


@pytest.mark.parametrize("p", [
    policy("apps", apps=("00000003-0000-0ff1-ce00-000000000000",)),
    policy("platform", extra_conditions={"platforms": {"includePlatforms": ["android"]}}),
    policy("client", extra_conditions={"clientAppTypes": ["browser"]}),
    policy("location", extra_conditions={"locations": {"includeLocations": ["x"]}}),
    policy("risk", extra_conditions={"signInRiskLevels": ["high"]}),
    policy("role", includeRoles=["r1"]),
    policy("exclgroup", excludeGroups=[G2]),
    policy("guests", excludeGuestsOrExternalUsers={"guestOrExternalUserTypes": "b2bCollaborationGuest"}),
    policy("or", grant={"operator": "OR", "builtInControls": ["mfa", "compliantDevice"]}),
])
def test_policies_membership_cannot_decide_never_pass(p):
    value, out = run(body([p], members=[U], groups=[G1]))
    assert value is not True
    assert value is None or "groupCoverage" not in out["transformedResponse"]


def test_existing_pass_and_fail_are_untouched_by_membership():
    passing = body([policy("All", include_users=("All",), include_groups=())], members=[[]], groups=[G1])
    assert run(passing)[0] is True
    failing = body([policy("A")], members=[U], groups=[G1])
    failing["authMethodsPolicy"] = {"authenticationMethodConfigurations": [{"id": "Sms", "state": "enabled"}]}
    assert run(failing)[0] is False  # no MFA method: fails as before, membership is not consulted


def test_membership_false_only_when_a_member_is_reached_by_no_mfa_policy():
    # Every combination of policy shape x membership outcome: False only where the no-membership input is False or
    # some enabled member is in no group or user list of any enabled MFA policy; True stays True.
    shapes = [policy("A"), policy("A", excludeUsers=U[:3]), policy("apps", apps=("x",)),
              policy("All", include_users=("All",), include_groups=(), excludeGroups=[G1])]
    outcomes = [[U], [U[:1]], [[]]]
    for shape in shapes:
        base, _ = run(body([shape]))
        for members in outcomes:
            value, _ = run(body([shape], members=members, groups=[G1]))
            reached = set(members[0]) if not shape["conditions"]["users"]["includeUsers"] else set(U)
            if value is False:
                assert base is False or set(U) - reached
            if base is True:
                assert value is True


# --- RestrictedPython -----------------------------------------------------------------------------------------------

def test_restricted_python_executes_and_agrees():
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
    for b in (body([policy("A")], members=[U], groups=[G1]), body([policy("A")], members=[U[:2]], groups=[G1]),
              body([policy("A"), policy("B", include_groups=(G2,))], members=[U[:3], U[3:]]),
              body([policy("A")])):
        s_out = glb["transform"](copy.deepcopy(b))
        p_out = M.transform(copy.deepcopy(b))
        assert s_out["transformedResponse"] == p_out["transformedResponse"]
        assert s_out["additionalInfo"]["evaluation"] == p_out["additionalInfo"]["evaluation"]
        assert s_out["additionalInfo"]["dataCollection"] == p_out["additionalInfo"]["dataCollection"]
