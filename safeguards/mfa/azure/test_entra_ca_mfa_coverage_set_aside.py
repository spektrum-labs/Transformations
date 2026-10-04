"""entra_ca_mfa_coverage.py: the reason names the policies set aside, and why (4 Oct 2026).

When no policy set covers the workforce, the reason lists the workforce MFA policies that did not count: excluded
group / role / guests, narrowed by platform, device filter or client type, limited to named locations, or no user
members read in the included groups. At most 5 are named, then "and N more"; names are cut to 80 characters. It
never produces a verdict. Synthetic estate only, typed JSON values.
"""
import copy
import importlib.util
import json
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
SOURCE = (HERE / "entra_ca_mfa_coverage.py").read_text()


def load():
    spec = importlib.util.spec_from_file_location("entra_ca_mfa_coverage_set_aside", HERE / "entra_ca_mfa_coverage.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


M = load()
U1 = "b0000000-0000-0000-0000-000000000001"
G_STAFF = "c0000000-0000-0000-0000-000000000001"
G_EMPTY = "c0000000-0000-0000-0000-0000000000e0"
CA_CTX = "https://graph.microsoft.com/v1.0/$metadata#identity/conditionalAccess/policies"


def all_users_policy(name, **users):
    cond_users = {"includeUsers": ["All"], "includeGroups": [], "includeRoles": []}
    cond_users.update(users)
    return {"displayName": name, "state": "enabled",
            "conditions": {"users": cond_users, "applications": {"includeApplications": ["All"]},
                           "clientAppTypes": ["all"]},
            "grantControls": {"operator": "OR", "builtInControls": ["mfa"]}}


def group_policy(name, group_ids, **conditions):
    p = {"displayName": name, "state": "enabled",
         "conditions": {"users": {"includeUsers": [], "includeGroups": list(group_ids), "includeRoles": []},
                        "applications": {"includeApplications": ["All"]}, "clientAppTypes": ["all"]},
         "grantControls": {"operator": "OR", "builtInControls": ["mfa"]}}
    p["conditions"].update(conditions)
    return p


def ca_of(*policies):
    return {"@odata.context": CA_CTX, "value": list(policies)}


def groups():
    return {"value": [{"id": g, "displayName": "G", "groupTypes": [], "membershipRule": None,
                       "membershipRuleProcessingState": None} for g in (G_STAFF, G_EMPTY)]}


def membership_body(policies):
    return {"conditionalAccessPolicies": ca_of(*policies), "groups": groups(),
            "workforceUsers": {"@odata.count": 1, "value": [{"id": U1, "accountEnabled": True, "userType": "Member"}]},
            "caPolicyGroups": {"groupIds": [{"id": G_STAFF}, {"id": G_EMPTY}]},
            "groupMembers": [{"@odata.count": 1, "value": [{"id": U1}]}, {"@odata.count": 0, "value": []}]}


def run(b, module=M):
    out = module.transform(copy.deepcopy(b))
    return out["transformedResponse"], out["additionalInfo"]


@pytest.mark.parametrize("users,label", [({"excludeGroups": [G_EMPTY]}, "excludes a group"),
                                         ({"excludeRoles": ["d0000000-0000-0000-0000-000000000001"]}, "excludes a directory role"),
                                         ({"excludeGuestsOrExternalUsers": {"guestOrExternalUserTypes": "b2bCollaborationGuest"}},
                                          "excludes guests or external users")])
def test_exclusions_are_named_with_a_short_label(users, label):
    res, info = run({"conditionalAccessPolicies": ca_of(all_users_policy("MFA everyone", **users))})
    assert res["isMFARequiredForRemoteAccess"] is None
    assert info["dataCollection"]["errors"][-1].endswith('policies set aside: "MFA everyone" (' + label + ")")


def test_narrowing_and_locations_and_empty_groups_are_named():
    res, info = run(membership_body([
        group_policy("iOS only", [G_STAFF], platforms={"includePlatforms": ["iOS"]}),
        group_policy("Office only", [G_STAFF], locations={"includeLocations": ["c0000000-0000-0000-0000-00000000000a"]}),
        group_policy("Empty", [G_EMPTY])]))
    assert res["isMFARequiredForRemoteAccess"] is None
    aside = res["remoteAccessPoliciesSetAside"]
    assert "iOS only (narrowed by platform, device filter or client type)" in aside
    assert "Office only (limited to named locations)" in aside
    assert "Empty (no user members read in its included groups)" in aside


def test_cap_at_five_and_truncate_names_to_80():
    policies = [group_policy("P" * 120 + str(i), [G_STAFF], platforms={"includePlatforms": ["android"]})
                for i in range(7)]
    res, info = run({"conditionalAccessPolicies": ca_of(*policies)})
    text = info["dataCollection"]["errors"][-1]
    assert text.count('" (') == 5 and text.endswith("and 2 more")
    assert all(len(entry.split(" (")[0]) <= 80 for entry in res["remoteAccessPoliciesSetAside"])
    assert ("P" * 77 + "...") in text


def test_covered_workforce_has_no_set_aside_and_verdicts_are_unchanged():
    res, info = run({"conditionalAccessPolicies": ca_of(all_users_policy("MFA everyone"),
                                                         group_policy("iOS only", [G_STAFF],
                                                                      platforms={"includePlatforms": ["iOS"]}))})
    assert res["isMFARequiredForRemoteAccess"] is True
    assert "remoteAccessPoliciesSetAside" not in res


def test_restricted_python_executes_and_agrees():
    pytest.importorskip("RestrictedPython")
    import builtins as real
    from RestrictedPython import compile_restricted, limited_builtins, safe_globals, utility_builtins
    from RestrictedPython.Eval import default_guarded_getitem, default_guarded_getiter
    from RestrictedPython.Guards import guarded_iter_unpack_sequence, guarded_unpack_sequence, safer_getattr
    for banned in ("getattr(", "re.compile", "strptime"):
        assert banned not in SOURCE
    code = compile_restricted(SOURCE, "<entra_ca_mfa_coverage>", "exec")
    allowed = {"json", "datetime", "warnings"}

    def guarded_import(name, *args, **kwargs):
        if name not in allowed:
            raise ImportError(name)
        return real.__import__(name, *args, **kwargs)

    names = dict(safe_globals["__builtins__"])
    names.update(limited_builtins)
    names.update(utility_builtins)
    names.update(__import__=guarded_import, isinstance=isinstance, list=list, dict=dict, str=str, any=any,
                 all=all, bytes=bytes, set=set, sorted=sorted, len=len, min=min, max=max, sum=sum, int=int,
                 ValueError=ValueError, Exception=Exception, enumerate=enumerate, tuple=tuple, bool=bool)
    glb = dict(safe_globals)
    glb.update(__builtins__=names, _getitem_=default_guarded_getitem, _getiter_=default_guarded_getiter,
               _iter_unpack_sequence_=guarded_iter_unpack_sequence, _unpack_sequence_=guarded_unpack_sequence,
               _getattr_=safer_getattr, _write_=lambda x: x, __name__="sandboxed", __metaclass__=type)
    exec(code, glb)
    bodies = (membership_body([group_policy("Empty", [G_EMPTY]), group_policy("iOS", [G_STAFF], platforms={"includePlatforms": ["iOS"]})]),
              {"conditionalAccessPolicies": ca_of(*[group_policy("P" * 90 + str(i), [G_STAFF],
                                                                 platforms={"includePlatforms": ["iOS"]}) for i in range(7)])},
              {"conditionalAccessPolicies": ca_of(all_users_policy("X", excludeGroups=[G_EMPTY]))})
    for b in bodies:
        sandboxed = glb["transform"](copy.deepcopy(b))
        plain = M.transform(copy.deepcopy(b))
        assert sandboxed["transformedResponse"] == plain["transformedResponse"]
        assert json.dumps(sandboxed["additionalInfo"]["dataCollection"]) == json.dumps(plain["additionalInfo"]["dataCollection"])
