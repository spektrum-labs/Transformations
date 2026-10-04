"""entra_ca_mfa_coverage.py: accountEnabled as a JSON boolean or the strings "true" / "false" (4 Oct 2026).

The Integration-Service workflow delivers the workforce list with accountEnabled as the string "True", so the
bool-only check read the list as unread at every tenant and group coverage never ran. Accepted now: a boolean, or
"true"/"false" in any case with surrounding whitespace. Anything else (missing, null, numbers, "yes", "1", "",
lists) still makes the list unread, exactly as before. Synthetic estate only.
"""
import copy
import importlib.util
import json
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
SOURCE = (HERE / "entra_ca_mfa_coverage.py").read_text()


def load():
    spec = importlib.util.spec_from_file_location("entra_ca_mfa_coverage_flags", HERE / "entra_ca_mfa_coverage.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


M = load()
U1 = "b0000000-0000-0000-0000-000000000001"
U2 = "b0000000-0000-0000-0000-000000000002"
U3 = "b0000000-0000-0000-0000-000000000003"
G_STAFF = "c0000000-0000-0000-0000-000000000001"
CA_CTX = "https://graph.microsoft.com/v1.0/$metadata#identity/conditionalAccess/policies"


def ca():
    return {"@odata.context": CA_CTX, "value": [{
        "displayName": "MFA Staff", "state": "enabled",
        "conditions": {"users": {"includeUsers": [], "includeGroups": [G_STAFF], "includeRoles": []},
                       "applications": {"includeApplications": ["All"]}, "clientAppTypes": ["all"]},
        "grantControls": {"operator": "OR", "builtInControls": ["mfa"]}}]}


def groups():
    return {"value": [{"id": G_STAFF, "displayName": "Staff", "groupTypes": [], "membershipRule": None,
                       "membershipRuleProcessingState": None}]}


def workforce(flags):
    value = [{"id": uid, "accountEnabled": flag, "userType": "Member", "displayName": "User " + uid[-1]}
             for uid, flag in flags]
    return {"@odata.context": "https://graph.microsoft.com/v1.0/$metadata#users", "@odata.count": len(value),
            "value": value}


def members(*ids):
    return {"@odata.count": len(ids), "value": [{"@odata.type": "#microsoft.graph.user", "id": i} for i in ids]}


def body(flags, member_ids):
    return {"conditionalAccessPolicies": ca(), "groups": groups(), "workforceUsers": workforce(flags),
            "caPolicyGroups": {"groupIds": [{"id": G_STAFF}]}, "groupMembers": [members(*member_ids)]}


def run(b, module=M):
    out = module.transform(copy.deepcopy(b))
    return out["transformedResponse"], out["additionalInfo"]


@pytest.mark.parametrize("true_value", [True, "True", "true", " TRUE ", "tRuE\n"])
def test_enabled_flag_as_boolean_or_string_reads_the_workforce(true_value):
    res, _ = run(body([(U1, true_value), (U2, true_value)], [U1, U2]))
    assert res["isMFARequiredForRemoteAccess"] is True
    assert res["isRDPProtected"] is True
    assert res["remoteAccessPoliciesGroupCoverage"]["membersTotal"] == 2


@pytest.mark.parametrize("false_value", [False, "False", "false", " FALSE "])
def test_disabled_accounts_as_string_are_left_out_of_the_workforce(false_value):
    # U3 is disabled and outside the group: it must not count against coverage.
    res, _ = run(body([(U1, "True"), (U2, "True"), (U3, false_value)], [U1, U2]))
    assert res["isMFARequiredForRemoteAccess"] is True
    assert res["remoteAccessPoliciesGroupCoverage"]["membersTotal"] == 2


def test_string_flags_still_report_members_outside_the_groups_and_never_fail():
    res, info = run(body([(U1, "True"), (U2, "True"), (U3, "True")], [U1, U2]))
    assert res["isMFARequiredForRemoteAccess"] is None
    assert "1 of 3 enabled members are outside the included groups" in info["dataCollection"]["errors"][-1]


@pytest.mark.parametrize("bad", [None, 1, 0, "yes", "no", "1", "0", "", "  ", "truthy", "True!", [], {}, ["True"]])
def test_any_other_enabled_value_leaves_the_list_unread_as_before(bad):
    flags = [(U1, "True"), (U2, bad)]
    if bad is None:
        b = body([(U1, "True")], [U1, U2])
        b["workforceUsers"]["value"].append({"id": U2, "userType": "Member"})
        b["workforceUsers"]["@odata.count"] = 2
    else:
        b = body(flags, [U1, U2])
    res, info = run(b)
    assert res["isMFARequiredForRemoteAccess"] is None
    assert res["isRDPProtected"] is None
    assert "could not be read whole" in " ".join(info["dataCollection"]["errors"])


def test_read_flag_contract():
    assert [M.read_flag(v) for v in (True, False, "True", "false", " TRUE ")] == [True, False, True, False, True]
    for v in (None, 1, 0, 1.0, "yes", "", "t", b"true", ["true"]):
        assert M.read_flag(v) is None


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
    for b in (body([(U1, "True"), (U2, "True")], [U1, U2]), body([(U1, "True"), (U2, "yes")], [U1, U2]),
              body([(U1, "True"), (U2, "True"), (U3, "True")], [U1, U2]), {"conditionalAccessPolicies": None},
              {"conditionalAccessPolicies": ca_of(all_users_policy("N", excludeGuestsOrExternalUsers="None"))},
              {"conditionalAccessPolicies": ca_of(*[group_policy("P" * 90 + str(i), [G_STAFF],
                                                                  platforms={"includePlatforms": ["iOS"]})
                                                     for i in range(7)])}):
        sandboxed = glb["transform"](copy.deepcopy(b))
        plain = M.transform(copy.deepcopy(b))
        assert sandboxed["transformedResponse"] == plain["transformedResponse"]
        assert sandboxed["additionalInfo"]["evaluation"] == plain["additionalInfo"]["evaluation"]
        assert json.dumps(sandboxed["additionalInfo"]["dataCollection"]) == json.dumps(plain["additionalInfo"]["dataCollection"])


# --- "None" as absent, and the set-aside reason (4 Oct 2026) ---------------------------------------------------------

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


@pytest.mark.parametrize("none", ["None", "none", " NONE "])
def test_stringified_null_exclusions_are_absent(none):
    p = all_users_policy("MFA everyone", excludeGuestsOrExternalUsers=none, excludeGroups=none, excludeRoles=none,
                         excludeUsers=none)
    p["conditions"]["devices"] = {"deviceFilter": {"mode": "include", "rule": none}}
    res, _ = run({"conditionalAccessPolicies": ca_of(p)})
    assert res["isMFARequiredForRemoteAccess"] is True
    assert res["isRDPProtected"] is True


@pytest.mark.parametrize("field,value", [("excludeGuestsOrExternalUsers", "someone"),
                                         ("excludeGuestsOrExternalUsers", {"guestOrExternalUserTypes": "b2bCollaborationGuest"}),
                                         ("excludeGroups", ["c0000000-0000-0000-0000-0000000000ee"]),
                                         ("excludeUsers", "a list that is not a list")])
def test_any_other_exclusion_value_still_blocks(field, value):
    res, info = run({"conditionalAccessPolicies": ca_of(all_users_policy("MFA everyone", **{field: value}))})
    assert res["isMFARequiredForRemoteAccess"] is None
    assert 'policies set aside: "MFA everyone" (excludes ' in info["dataCollection"]["errors"][-1]


def test_device_filter_rule_other_than_none_still_narrows():
    p = all_users_policy("MFA everyone")
    p["conditions"]["devices"] = {"deviceFilter": {"mode": "include", "rule": 'device.isCompliant -eq True'}}
    res, info = run({"conditionalAccessPolicies": ca_of(p)})
    assert res["isMFARequiredForRemoteAccess"] is None
    assert '"MFA everyone" (narrowed by platform, device filter or client type)' in info["dataCollection"]["errors"][-1]


def test_set_aside_names_why_caps_at_five_and_truncates_names():
    long_name = "L" * 120
    policies = [group_policy("Platform " + str(i), [G_STAFF], platforms={"includePlatforms": ["iOS"]}) for i in range(5)]
    policies.append(group_policy(long_name, [G_STAFF], locations={"includeLocations": ["c0000000-0000-0000-0000-00000000000a"]}))
    policies.append(group_policy("Empty group", ["c0000000-0000-0000-0000-0000000000e0"]))
    b = {"conditionalAccessPolicies": ca_of(*policies), "groups": groups(),
         "workforceUsers": workforce([(U1, "True")]),
         "caPolicyGroups": {"groupIds": [{"id": G_STAFF}, {"id": "c0000000-0000-0000-0000-0000000000e0"}]},
         "groupMembers": [members(U1), members()]}
    res, info = run(b)
    assert res["isMFARequiredForRemoteAccess"] is None
    text = info["dataCollection"]["errors"][-1]
    assert text.count('" (') == 5 and "and 2 more" in text
    assert '"Platform 0" (narrowed by platform, device filter or client type)' in text
    aside = res["remoteAccessPoliciesSetAside"]
    assert len(aside) == 7
    assert ("L" * 77 + "... (limited to named locations)") in aside
    assert "Empty group (no user members read in its included groups)" in aside
    assert all(len(entry.split(" (")[0]) <= 80 for entry in aside)


def test_set_aside_never_turns_a_key_into_a_verdict():
    for pol in (all_users_policy("X", excludeGroups=["c0000000-0000-0000-0000-0000000000ee"]),
                group_policy("Y", [G_STAFF], platforms={"includePlatforms": ["android"]})):
        res, _ = run({"conditionalAccessPolicies": ca_of(pol)})
        assert res["isMFARequiredForRemoteAccess"] is None and res["isRDPProtected"] is None
