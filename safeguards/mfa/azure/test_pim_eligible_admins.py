"""Microsoft Entra ID: administrators who hold a privileged role only through PIM eligibility are counted.

GET /roleManagement/directory/roleAssignments returns ACTIVE assignments only, so a tenant that uses Privileged
Identity Management (PIM) and holds its admin roles as ELIGIBLE assignments looked admin-free to the admin checks.
The workflow now also merges GET /v1.0/roleManagement/directory/roleEligibilityScheduleInstances (every page) under
"roleEligibilityScheduleInstances". For each transform this file proves:

  * a PIM-only tenant (admins only eligible) now has its admins found and judged;
  * active and eligible admins are counted separately (activeAdminCount, eligibleAdminCount);
  * the key ABSENT gives the verdict the transform gave before, with eligibleAssignmentsRead false;
  * the key PRESENT but not read whole (@odata.nextLink, a vendorErrorAsResponse marker, a 403 error body) never
    passes on the partial admin set;
  * an eligibility instance that has ended, or not begun, does not count.

Synthetic data only: made-up object ids and placeholder names. Role template ids are Microsoft's published,
tenant-independent ids. Every case runs as plain Python and in the Token-Service sandbox replica.
"""
import copy
import importlib.util
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SG = ROOT / "safeguards"

GA = "62e90394-69f5-4237-9190-012177145e10"      # Global Administrator
SEC = "194ae4cb-b126-40b2-bd5b-6091b380977d"     # Security Administrator
READER = "88d8e3e3-8f55-4a1e-953a-9b9898b8876b"  # Directory Readers: not in the privileged lists
E3 = "6fd2c87f-b296-42f0-b197-1e91e994b900"      # Office 365 E3: carries a mailbox
P2 = "84a661c4-e949-4bd2-a560-ed7766fcaf2b"      # Entra ID P2: no mailbox

ACTIVE = "aaaaaaaa-0000-4000-8000-000000000001"
ELIGIBLE = "bbbbbbbb-0000-4000-8000-000000000002"
BOTH = "cccccccc-0000-4000-8000-000000000003"
OTHER = "dddddddd-0000-4000-8000-000000000004"
GROUP = "eeeeeeee-0000-4000-8000-000000000005"

USER_T = "#microsoft.graph.user"
GROUP_T = "#microsoft.graph.group"
NEXT = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?$skiptoken=x"


def _sandbox_loader():
    spec = importlib.util.spec_from_file_location("restricted_sandbox_pim", ROOT / "tools" / "restricted_sandbox.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.load


SANDBOX_LOAD = _sandbox_loader()
CACHE = {}


def load(path, mode):
    key = (str(path), mode)
    if key not in CACHE:
        if mode == "native":
            spec = importlib.util.spec_from_file_location("pim_" + str(abs(hash(str(path)))), path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            CACHE[key] = module.transform
        else:
            CACHE[key] = SANDBOX_LOAD(path.read_text(), "<transformation>")["transform"]
    return CACHE[key]


def params(paths):
    out = []
    for path in paths:
        for mode in ("native", "sandbox"):
            out.append(pytest.param(path, mode, id=path.parent.name[:8] + "-" + mode))
    return out


def ra(pid, role=GA, ptype=USER_T):
    return {"id": "ra-" + pid[:8], "principalId": pid, "roleDefinitionId": role, "directoryScopeId": "/",
            "principal": {"@odata.type": ptype, "id": pid}}


def ei(pid, role=GA, ptype=USER_T, start="2025-01-01T00:00:00Z", end=None):
    return {"id": "ei-" + pid[:8], "principalId": pid, "roleDefinitionId": role, "directoryScopeId": "/",
            "memberType": "Direct", "startDateTime": start, "endDateTime": end,
            "principal": {"@odata.type": ptype, "id": pid}}


def graph(rows, **extra):
    body = {"@odata.context": "https://graph.microsoft.com/v1.0/$metadata#collection", "value": rows}
    body.update(extra)
    return body


INCOMPLETE = {
    "next_link": graph([ei(ELIGIBLE)], **{"@odata.nextLink": NEXT}),
    "vendor_error": {"vendorErrorAsResponse": {"status": 403, "body": {"error": {
        "code": "AadPremiumLicenseRequired", "message": "placeholder"}}}},
    "error_403": {"error": {"code": "Authorization_RequestDenied", "message": "placeholder"}},
    "not_a_list": {"value": "unexpected"},
}


def info(out):
    return out["additionalInfo"]


def status(out):
    return info(out)["dataCollection"]["status"]


# ============================================================================ areAdminAccountsSeparate (M365 file)

SEP_M365 = SG / "874a78ff-2ca3-4c0e-ab86-19277536ac87" / "areadminaccountsseparate.py"
SEP_AZURE = SG / "mfa" / "azure" / "areadminaccountsseparate.py"


def sep_user(uid, skus=(), mail=None):
    return {"id": uid, "userPrincipalName": "placeholder-" + uid[:4] + "@example.test", "mail": mail,
            "accountEnabled": True, "assignedLicenses": [{"skuId": s, "disabledPlans": []} for s in skus]}


def sep_body(assignments, eligible=None, users=None):
    body = {"roleAssignments": graph(assignments),
            "users": graph(users if users is not None else [sep_user(ACTIVE, [P2]), sep_user(ELIGIBLE, [P2]),
                                                             sep_user(BOTH), sep_user(OTHER, [E3])])}
    if eligible is not None:
        body["roleEligibilityScheduleInstances"] = eligible
    return body


SEP_KEY = "areAdminAccountsSeparate"


@pytest.mark.parametrize("path,mode", params([SEP_M365, SEP_AZURE]))
def test_separate_pim_only_tenant_finds_and_fails_the_eligible_admin(path, mode):
    # No active privileged assignment at all; the only admin holds Global Administrator through PIM and has E3.
    users = [sep_user(ACTIVE, [P2]), sep_user(ELIGIBLE, [E3])]
    out = load(path, mode)(sep_body([ra(OTHER, role=READER)], graph([ei(ELIGIBLE)]), users))
    result = out["transformedResponse"]
    assert result[SEP_KEY] is False and status(out) == "success"
    assert result["adminCount"] == 1
    assert result["activeAdminCount"] == 0 and result["eligibleAdminCount"] == 1
    assert result["eligibleAssignmentsRead"] is True
    reasons = " ".join(info(out)["evaluation"]["failReasons"])
    assert ELIGIBLE[:8] in reasons and "@example.test" not in reasons


@pytest.mark.parametrize("path,mode", params([SEP_M365, SEP_AZURE]))
def test_separate_pim_only_tenant_with_dedicated_admin_passes(path, mode):
    users = [sep_user(ELIGIBLE, [P2]), sep_user(OTHER, [E3])]
    out = load(path, mode)(sep_body([], graph([ei(ELIGIBLE)]), users))
    assert out["transformedResponse"][SEP_KEY] is True and status(out) == "success"
    assert out["transformedResponse"]["eligibleAdminCount"] == 1


@pytest.mark.parametrize("path,mode", params([SEP_M365, SEP_AZURE]))
def test_separate_mixed_active_and_eligible_are_counted_by_kind(path, mode):
    eligible = graph([ei(ELIGIBLE), ei(BOTH, role=SEC)])
    out = load(path, mode)(sep_body([ra(ACTIVE), ra(BOTH)], eligible))
    result = out["transformedResponse"]
    assert result[SEP_KEY] is True
    assert result["adminCount"] == 3
    assert result["activeAdminCount"] == 2 and result["eligibleAdminCount"] == 2


@pytest.mark.parametrize("path,mode", params([SEP_M365, SEP_AZURE]))
def test_separate_key_absent_keeps_the_old_verdict_and_says_so(path, mode):
    body = sep_body([ra(ACTIVE), ra(BOTH)])
    out = load(path, mode)(body)
    result = out["transformedResponse"]
    assert result[SEP_KEY] is True and status(out) == "success"
    assert result["adminCount"] == 2 and result["activeAdminCount"] == 2
    assert result["eligibleAssignmentsRead"] is False and result["eligibleAdminCount"] is None
    assert any("PIM-eligible" in f for f in info(out)["evaluation"]["additionalFindings"])


@pytest.mark.parametrize("path,mode", params([SEP_M365, SEP_AZURE]))
@pytest.mark.parametrize("case", sorted(INCOMPLETE))
def test_separate_incomplete_eligibility_read_never_passes(path, mode, case):
    out = load(path, mode)(sep_body([ra(ACTIVE)], copy.deepcopy(INCOMPLETE[case])))
    assert out["transformedResponse"][SEP_KEY] is False
    assert status(out) == "error"
    assert any("eligibility" in e for e in info(out)["dataCollection"]["errors"])


@pytest.mark.parametrize("path,mode", params([SEP_M365, SEP_AZURE]))
def test_separate_incomplete_eligibility_read_still_fails_a_proven_violation(path, mode):
    body = sep_body([ra(OTHER)], copy.deepcopy(INCOMPLETE["next_link"]))
    out = load(path, mode)(body)
    assert out["transformedResponse"][SEP_KEY] is False and status(out) == "success"


@pytest.mark.parametrize("path,mode", params([SEP_M365, SEP_AZURE]))
def test_separate_ended_and_future_eligibility_do_not_count(path, mode):
    eligible = graph([ei(OTHER, end="2020-01-01T00:00:00Z"), ei(OTHER, start="2999-01-01T00:00:00.0000000Z")])
    out = load(path, mode)(sep_body([ra(ACTIVE)], eligible))
    assert out["transformedResponse"][SEP_KEY] is True
    assert out["transformedResponse"]["eligibleAdminCount"] == 0


@pytest.mark.parametrize("path,mode", params([SEP_M365, SEP_AZURE]))
def test_separate_eligible_group_stays_unresolved(path, mode):
    out = load(path, mode)(sep_body([ra(ACTIVE)], graph([ei(GROUP, ptype=GROUP_T)])))
    assert out["transformedResponse"][SEP_KEY] is False and status(out) == "error"


@pytest.mark.parametrize("path,mode", params([SEP_M365, SEP_AZURE]))
def test_separate_eligibility_as_bare_list_and_page_list(path, mode):
    users = [sep_user(ELIGIBLE, [P2])]
    for eligible in ([ei(ELIGIBLE)], [graph([ei(ELIGIBLE)]), graph([])]):
        out = load(path, mode)(sep_body([], eligible, users))
        assert out["transformedResponse"][SEP_KEY] is True, eligible
        assert out["transformedResponse"]["eligibleAdminCount"] == 1


@pytest.mark.parametrize("path,mode", params([SEP_AZURE]))
def test_separate_azure_eligible_list_alone_is_not_the_whole_population(path, mode):
    users = [sep_user(ELIGIBLE, [P2])]
    body = {"users": graph(users), "roleEligibilityScheduleInstances": graph([ei(ELIGIBLE)])}
    out = load(path, mode)(body)
    assert out["transformedResponse"][SEP_KEY] is False and status(out) == "error"


# ============================================================================ areAdminAccountsSeparate (One-Click feed)

SEP_RA = SG / "mfa" / "azure" / "areadminaccountsseparate_roleassignments.py"


@pytest.mark.parametrize("path,mode", params([SEP_RA]))
def test_roleassignments_pim_only_tenant_now_evaluates(path, mode):
    users = [sep_user(ELIGIBLE), sep_user(OTHER, [E3])]
    before = load(path, mode)(sep_body([], None, users))
    assert before["transformedResponse"][SEP_KEY] is None  # no admin found: unevaluated, as before
    out = load(path, mode)(sep_body([], graph([ei(ELIGIBLE)]), users))
    result = out["transformedResponse"]
    assert result[SEP_KEY] is True and status(out) == "success"
    assert result["activeAdminCount"] == 0 and result["eligibleAdminCount"] == 1


@pytest.mark.parametrize("path,mode", params([SEP_RA]))
def test_roleassignments_mixed_and_named_by_object_id(path, mode):
    users = [sep_user(ACTIVE), sep_user(ELIGIBLE, [E3]), sep_user(BOTH)]
    out = load(path, mode)(sep_body([ra(ACTIVE), ra(BOTH)], graph([ei(ELIGIBLE), ei(BOTH)]), users))
    result = out["transformedResponse"]
    assert result[SEP_KEY] is False
    assert result["adminCount"] == 3 and result["activeAdminCount"] == 2 and result["eligibleAdminCount"] == 2
    reason = info(out)["evaluation"]["failReasons"][0]
    assert ELIGIBLE[:8] in reason and "@example.test" not in reason


@pytest.mark.parametrize("path,mode", params([SEP_RA]))
def test_roleassignments_key_absent_old_verdict_and_flag(path, mode):
    users = [sep_user(ACTIVE)]
    out = load(path, mode)(sep_body([ra(ACTIVE)], None, users))
    assert out["transformedResponse"][SEP_KEY] is True
    assert out["transformedResponse"]["eligibleAssignmentsRead"] is False
    assert any("PIM-eligible" in f for f in info(out)["evaluation"]["additionalFindings"])


@pytest.mark.parametrize("path,mode", params([SEP_RA]))
@pytest.mark.parametrize("case", sorted(INCOMPLETE))
def test_roleassignments_incomplete_eligibility_is_unevaluated(path, mode, case):
    users = [sep_user(ACTIVE)]
    out = load(path, mode)(sep_body([ra(ACTIVE)], copy.deepcopy(INCOMPLETE[case]), users))
    assert out["transformedResponse"][SEP_KEY] is None and status(out) == "error"


@pytest.mark.parametrize("path,mode", params([SEP_RA]))
def test_roleassignments_eligible_group_is_unevaluated(path, mode):
    users = [sep_user(ACTIVE)]
    out = load(path, mode)(sep_body([ra(ACTIVE)], graph([ei(GROUP, ptype=GROUP_T)]), users))
    assert out["transformedResponse"][SEP_KEY] is None and status(out) == "error"


# ============================================================================ arePrivilegedAccountsCloudOnly

CLOUD = [SG / "mfa" / "azure" / "areprivilegedaccountscloudonly.py",
         SG / "874a78ff-2ca3-4c0e-ab86-19277536ac87" / "areprivilegedaccountscloudonly.py"]
CLOUD_KEY = "arePrivilegedAccountsCloudOnly"


def cloud_user(uid, synced=None):
    return {"id": uid, "userPrincipalName": "placeholder-" + uid[:4] + "@example.test", "accountEnabled": True,
            "onPremisesSyncEnabled": synced, "onPremisesImmutableId": None}


def cloud_body(assignments, eligible=None, users=None, **extra):
    body = {"roleAssignments": graph(assignments),
            "users": graph(users if users is not None else [cloud_user(ACTIVE), cloud_user(ELIGIBLE),
                                                             cloud_user(BOTH), cloud_user(OTHER, True)])}
    if eligible is not None:
        body["roleEligibilityScheduleInstances"] = eligible
    body.update(extra)
    return body


def test_cloudonly_copies_stay_identical():
    assert CLOUD[0].read_bytes() == CLOUD[1].read_bytes()


@pytest.mark.parametrize("path,mode", params(CLOUD))
def test_cloudonly_pim_only_tenant_finds_the_synced_eligible_admin(path, mode):
    before = load(path, mode)(cloud_body([]))
    assert before["transformedResponse"][CLOUD_KEY] is None  # no admin seen: not evaluated, as before
    out = load(path, mode)(cloud_body([], graph([ei(OTHER)])))
    result = out["transformedResponse"]
    assert result[CLOUD_KEY] is False and status(out) == "success"
    assert result["privilegedUserCount"] == 1
    assert result["activeAdminCount"] == 0 and result["eligibleAdminCount"] == 1


@pytest.mark.parametrize("path,mode", params(CLOUD))
def test_cloudonly_mixed_counts(path, mode):
    out = load(path, mode)(cloud_body([ra(ACTIVE), ra(BOTH)], graph([ei(ELIGIBLE), ei(BOTH)])))
    result = out["transformedResponse"]
    assert result[CLOUD_KEY] is True
    assert result["privilegedUserCount"] == 3
    assert result["activeAdminCount"] == 2 and result["eligibleAdminCount"] == 2


@pytest.mark.parametrize("path,mode", params(CLOUD))
def test_cloudonly_key_absent_old_verdict_and_flag(path, mode):
    out = load(path, mode)(cloud_body([ra(ACTIVE)]))
    result = out["transformedResponse"]
    assert result[CLOUD_KEY] is True and result["eligibleAssignmentsRead"] is False
    assert result["eligibleAdminCount"] is None
    assert any("PIM-eligible" in f for f in info(out)["evaluation"]["additionalFindings"])


@pytest.mark.parametrize("path,mode", params(CLOUD))
@pytest.mark.parametrize("case", sorted(INCOMPLETE))
def test_cloudonly_incomplete_eligibility_is_not_evaluated(path, mode, case):
    out = load(path, mode)(cloud_body([ra(ACTIVE)], copy.deepcopy(INCOMPLETE[case])))
    assert out["transformedResponse"][CLOUD_KEY] is None and status(out) == "error"


@pytest.mark.parametrize("path,mode", params(CLOUD))
def test_cloudonly_eligible_group_is_expanded_like_an_active_one(path, mode):
    members = graph([{"@odata.type": USER_T, "id": OTHER, "onPremisesSyncEnabled": True}])
    expanded = {"roleGroups": {"groupIds": [{"id": GROUP}]}, "roleGroupMembers": [members]}
    out = load(path, mode)(cloud_body([ra(ACTIVE)], graph([ei(GROUP, ptype=GROUP_T)]), **expanded))
    result = out["transformedResponse"]
    assert result[CLOUD_KEY] is False and status(out) == "success"
    assert result["eligibleAdminCount"] == 1 and result["activeAdminCount"] == 1
    unexpanded = load(path, mode)(cloud_body([ra(ACTIVE)], graph([ei(GROUP, ptype=GROUP_T)])))
    assert unexpanded["transformedResponse"][CLOUD_KEY] is None and status(unexpanded) == "error"


# ============================================================================ staleAdminAccountCount

STALE = [SG / "mfa" / "azure" / "staleadminaccountcount.py",
         SG / "d9b6f27a-2e67-4b55-a09e-0784c5de9abd" / "staleadminaccountcount.py"]
STALE_KEY = "staleAdminAccountCount"


def iso(days_ago):
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def stale_user(uid, last_days):
    return {"id": uid, "userPrincipalName": "placeholder-" + uid[:4] + "@example.test", "accountEnabled": True,
            "userType": "Member", "createdDateTime": iso(900),
            "signInActivity": {"lastSuccessfulSignInDateTime": iso(last_days)}}


def stale_body(assignments, eligible=None):
    body = {"roleAssignments": graph(assignments),
            "users": graph([stale_user(ACTIVE, 3), stale_user(ELIGIBLE, 200), stale_user(BOTH, 5),
                            stale_user(OTHER, 400)])}
    if eligible is not None:
        body["roleEligibilityScheduleInstances"] = eligible
    return body


def test_stale_copies_stay_identical():
    assert STALE[0].read_bytes() == STALE[1].read_bytes()


@pytest.mark.parametrize("path,mode", params(STALE))
def test_stale_pim_only_tenant_counts_the_eligible_admin(path, mode):
    before = load(path, mode)(stale_body([]))
    assert before["transformedResponse"][STALE_KEY] is None
    out = load(path, mode)(stale_body([], graph([ei(ELIGIBLE)])))
    result = out["transformedResponse"]
    assert result[STALE_KEY] == 1 and status(out) == "success"
    assert result["adminCount"] == 1 and result["activeAdminCount"] == 0 and result["eligibleAdminCount"] == 1
    summary = info(out)["transformation"]["inputSummary"]
    assert summary["pimEligibleCovered"] is True
    assert "PIM-eligible" in info(out)["evaluation"]["failReasons"][0]


@pytest.mark.parametrize("path,mode", params(STALE))
def test_stale_mixed_counts(path, mode):
    out = load(path, mode)(stale_body([ra(ACTIVE), ra(BOTH)], graph([ei(ELIGIBLE, role=READER), ei(BOTH)])))
    result = out["transformedResponse"]
    assert result[STALE_KEY] == 1
    assert result["adminCount"] == 3 and result["activeAdminCount"] == 2 and result["eligibleAdminCount"] == 2


@pytest.mark.parametrize("path,mode", params(STALE))
def test_stale_key_absent_old_answer_and_flag(path, mode):
    out = load(path, mode)(stale_body([ra(ACTIVE)]))
    result = out["transformedResponse"]
    assert result[STALE_KEY] == 0 and result["adminCount"] == 1
    assert result["eligibleAssignmentsRead"] is False and result["eligibleAdminCount"] is None
    assert info(out)["transformation"]["inputSummary"]["pimEligibleCovered"] is False


@pytest.mark.parametrize("path,mode", params(STALE))
@pytest.mark.parametrize("case", sorted(INCOMPLETE))
def test_stale_incomplete_eligibility_is_unevaluated(path, mode, case):
    out = load(path, mode)(stale_body([ra(ACTIVE)], copy.deepcopy(INCOMPLETE[case])))
    assert out["transformedResponse"][STALE_KEY] is None and status(out) == "error"


@pytest.mark.parametrize("path,mode", params(STALE))
def test_stale_ended_eligibility_is_not_an_admin(path, mode):
    out = load(path, mode)(stale_body([ra(ACTIVE)], graph([ei(OTHER, end="2020-01-01T00:00:00Z")])))
    assert out["transformedResponse"][STALE_KEY] == 0
    assert out["transformedResponse"]["eligibleAdminCount"] == 0


# ============================================================================ MFA affected-account helpers

MFA_ADMINS = SG / "mfa" / "azure" / "ismfaenforcedforadmins.py"
MFA_SEC = SG / "mfa" / "azure" / "ismfaconfiguredforsecurityadmins.py"


def reg(uid, registered):
    return {"id": uid, "userPrincipalName": "placeholder-" + uid[:4] + "@example.test", "isMfaRegistered": registered}


def mfa_body(eligible=None):
    body = {"conditionalAccessPolicies": graph([]), "securityDefaults": {"isEnabled": True},
            "roleAssignments": graph([ra(ACTIVE)]),
            "registrationDetails": graph([reg(ACTIVE, True), reg(ELIGIBLE, False)])}
    if eligible is not None:
        body["roleEligibilityScheduleInstances"] = eligible
    return body


@pytest.mark.parametrize("path,mode", params([MFA_ADMINS]))
def test_mfa_admins_names_the_eligible_holder_and_keeps_the_verdict(path, mode):
    before = load(path, mode)(mfa_body())
    out = load(path, mode)(mfa_body(graph([ei(ELIGIBLE)])))
    assert out["transformedResponse"] == before["transformedResponse"]
    assert info(before)["transformation"]["inputSummary"]["affectedAccountCount"] == 0
    assert info(before)["transformation"]["inputSummary"]["eligibleAssignmentsRead"] is False
    summary = info(out)["transformation"]["inputSummary"]
    assert summary["affectedAccountCount"] == 1 and summary["eligibleAssignmentsRead"] is True
    assert "active and PIM-eligible holders" in info(out)["evaluation"]["passReasons"][0]
    partial = load(path, mode)(mfa_body(copy.deepcopy(INCOMPLETE["next_link"])))
    assert partial["transformedResponse"] == before["transformedResponse"]
    assert info(partial)["transformation"]["inputSummary"]["eligibleAssignmentsRead"] is False


def test_mfa_security_admins_helper_reads_eligible_holders():
    spec = importlib.util.spec_from_file_location("pim_secadmins", MFA_SEC)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    data = mfa_body(graph([ei(ELIGIBLE, role=SEC)]))
    accounts = module.admin_accounts(data, module.SECURITY_ADMIN_ROLES, [])
    assert accounts["total"] == 2 and accounts["eligibleRead"] is True
    assert len(accounts["affected"]) == 1
    without = module.admin_accounts(mfa_body(), module.SECURITY_ADMIN_ROLES, [])
    assert without["total"] == 1 and without["eligibleRead"] is False


# ============================================================================ isPrivilegedIdentityManagementEnabled

PIM = [SG / "mfa" / "azure" / "isprivilegedidentitymanagementenabled.py",
       SG / "d9b6f27a-2e67-4b55-a09e-0784c5de9abd" / "isprivilegedidentitymanagementenabled.py"]
PIM_KEY = "isPrivilegedIdentityManagementEnabled"


def test_pim_copies_stay_identical():
    assert PIM[0].read_bytes() == PIM[1].read_bytes()


@pytest.mark.parametrize("path,mode", params(PIM))
def test_pim_counts_every_row_of_a_full_paged_read(path, mode):
    rows = [ei(ACTIVE), ei(ELIGIBLE), ei(BOTH)]
    for body in (graph(rows), rows, [graph(rows[:2]), graph(rows[2:])],
                 {"roleEligibilityScheduleInstances": graph(rows)}, json.dumps(graph(rows))):
        out = load(path, mode)(body)
        assert out["transformedResponse"] == {PIM_KEY: True, "scheduleCount": 3}, body
        assert info(out)["transformation"]["inputSummary"]["scheduleCountComplete"] is True


@pytest.mark.parametrize("path,mode", params(PIM))
def test_pim_partial_read_reports_a_lower_bound(path, mode):
    out = load(path, mode)(graph([ei(ACTIVE)], **{"@odata.nextLink": NEXT}))
    assert out["transformedResponse"] == {PIM_KEY: True, "scheduleCount": 1}
    assert info(out)["transformation"]["inputSummary"]["scheduleCountComplete"] is False
    empty = load(path, mode)(graph([], **{"@odata.nextLink": NEXT}))
    assert empty["transformedResponse"][PIM_KEY] is False and status(empty) == "error"


@pytest.mark.parametrize("path,mode", params(PIM))
def test_pim_rows_that_are_not_schedules_do_not_count(path, mode):
    for body in ({"value": [{}]}, [{"vendorErrorAsResponse": {"status": 403}}], {}):
        out = load(path, mode)(body)
        assert out["transformedResponse"][PIM_KEY] is False, body


# ============================================================================ follow-up review of #1442
# 1. PIM-eligible holders only ADD to an ACTIVE read that succeeded. When roleAssignments is an error, a refusal,
#    {}, an unreadable page list or missing, one clean eligible admin used to pass areAdminAccountsSeparate and
#    arePrivilegedAccountsCloudOnly (before #1442: not evaluated). Every admin check now stays not evaluated.
# 2. A truncation marker on the eligibility read (response_metadata.paginationTruncated, pagination.truncated, a
#    flag on a wrapper object, paginationStats) is an incomplete read, never a complete one.

GRAPH_ERROR = {"error": {"code": "Authorization_RequestDenied", "message": "placeholder"}}
BROKEN_ACTIVE = {
    "error_body": GRAPH_ERROR,
    "vendor_403": {"vendorErrorAsResponse": {"status": 403, "body": GRAPH_ERROR}},
    "status_403": {"statusCode": 403, "message": "placeholder"},
    "empty_object": {},
    "wrapped_error": {"apiResponse": GRAPH_ERROR},
    "page_list_with_error": [graph([]), GRAPH_ERROR],
    "page_list_unparseable": [{"value": "x"}, {"value": "y"}],
    "page_list_mixed": [graph([]), {"placeholder": 1}],
    "row_without_principal": graph([{}]),
    "absent": None,
    # Second review of the follow-up: an empty value list beside an error marker, or inside an error wrapper.
    "status_error": graph([], status="error"),
    "http_status_403": graph([], httpStatus=403),
    "success_false": graph([], success=False),
    "errors_list": graph([], errors=["placeholder"]),
    "error_wrapper": {"error": {"code": "Forbidden", "message": "placeholder"}, "apiResponse": graph([])},
    "status_wrapper": {"status": "error", "response": graph([])},
}


def broken_active_body(path, case):
    """A tenant whose only privileged holder is a clean PIM-eligible admin, beside a broken active read."""
    if path in STALE:
        users = [stale_user(ELIGIBLE, 3)]
    elif path in CLOUD:
        users = [cloud_user(ELIGIBLE)]
    else:
        users = [sep_user(ELIGIBLE, [P2])]
    body = {"users": graph(users), "roleEligibilityScheduleInstances": graph([ei(ELIGIBLE)])}
    if BROKEN_ACTIVE[case] is not None:
        body["roleAssignments"] = copy.deepcopy(BROKEN_ACTIVE[case])
    return body


ADMIN_CHECKS = [(SEP_AZURE, SEP_KEY), (SEP_M365, SEP_KEY), (SEP_RA, SEP_KEY), (CLOUD[0], CLOUD_KEY),
                (CLOUD[1], CLOUD_KEY), (STALE[0], STALE_KEY), (STALE[1], STALE_KEY)]


def admin_params():
    out = []
    for path, key in ADMIN_CHECKS:
        for mode in ("native", "sandbox"):
            out.append(pytest.param(path, key, mode, id=path.parent.name[:8] + "-" + path.stem[:12] + "-" + mode))
    return out


@pytest.mark.parametrize("path,key,mode", admin_params())
@pytest.mark.parametrize("case", sorted(BROKEN_ACTIVE))
def test_broken_active_read_is_never_replaced_by_eligibility(path, key, mode, case):
    out = load(path, mode)(broken_active_body(path, case))
    value = out["transformedResponse"][key]
    assert value is not True, (case, value)
    if path in STALE or path in CLOUD or path == SEP_RA:
        assert value is None, (case, value)
    assert status(out) == "error", case


@pytest.mark.parametrize("path,mode", params([SEP_AZURE, SEP_M365]))
def test_separate_clean_page_list_active_read_still_adds_eligible_admins(path, mode):
    users = [sep_user(ACTIVE, [P2]), sep_user(ELIGIBLE, [P2])]
    body = sep_body([], graph([ei(ELIGIBLE)]), users)
    body["roleAssignments"] = [graph([ra(ACTIVE)]), graph([])]
    out = load(path, mode)(body)
    result = out["transformedResponse"]
    assert result[SEP_KEY] is True and status(out) == "success"
    assert result["activeAdminCount"] == 1 and result["eligibleAdminCount"] == 1


@pytest.mark.parametrize("path,mode", params([SEP_AZURE, SEP_M365]))
def test_separate_page_list_with_next_link_is_truncated(path, mode):
    body = sep_body([], graph([ei(ELIGIBLE)]), [sep_user(ACTIVE, [P2]), sep_user(ELIGIBLE, [P2])])
    body["roleAssignments"] = [graph([ra(ACTIVE)], **{"@odata.nextLink": NEXT})]
    out = load(path, mode)(body)
    assert out["transformedResponse"][SEP_KEY] is not True and status(out) == "error"


@pytest.mark.parametrize("path,mode", params(CLOUD))
def test_cloudonly_clean_page_list_active_read_still_adds_eligible_admins(path, mode):
    body = cloud_body([], graph([ei(ELIGIBLE)]), [cloud_user(ACTIVE), cloud_user(ELIGIBLE)])
    body["roleAssignments"] = [graph([ra(ACTIVE)]), graph([])]
    out = load(path, mode)(body)
    result = out["transformedResponse"]
    assert result[CLOUD_KEY] is True and status(out) == "success"
    assert result["activeAdminCount"] == 1 and result["eligibleAdminCount"] == 1


@pytest.mark.parametrize("module_path", [MFA_ADMINS, MFA_SEC])
@pytest.mark.parametrize("case", sorted(BROKEN_ACTIVE))
def test_mfa_helpers_name_no_eligible_holder_beside_a_broken_active_read(module_path, case):
    spec = importlib.util.spec_from_file_location("pim_helper_" + module_path.stem, module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    roles = module.SECURITY_ADMIN_ROLES if module_path == MFA_SEC else module.ADMIN_ROLES
    data = mfa_body(graph([ei(ELIGIBLE, role=SEC)]))
    if BROKEN_ACTIVE[case] is None:
        del data["roleAssignments"]
    else:
        data["roleAssignments"] = copy.deepcopy(BROKEN_ACTIVE[case])
    accounts = module.admin_accounts(data, roles, [])
    assert accounts is None or accounts == {"read": False}, (case, accounts)


TRUNCATED_ELIGIBILITY = {
    "response_metadata": lambda rows: graph(rows, response_metadata={"paginationTruncated": True}),
    "pagination_block": lambda rows: graph(rows, pagination={"truncated": True}),
    "wrapper_flag": lambda rows: {"apiResponse": graph(rows), "paginationTruncated": True},
    "wrapper_metadata": lambda rows: {"response": graph(rows), "response_metadata": {"paginationTruncated": "true"}},
    "iterate_truncated": lambda rows: graph(rows, iterateTruncated=True),
    "page_list_flag": lambda rows: [graph(rows), graph([], response_metadata={"paginationTruncated": True})],
}


def truncated_body(path, case, stats=False):
    """A PIM-only tenant with a clean eligible admin: a missed truncation marker would read as a pass."""
    rows = [ei(ELIGIBLE)]
    eligible = graph(rows) if stats else TRUNCATED_ELIGIBILITY[case](rows)
    if path in STALE:
        body = stale_body([], eligible)
        body["users"] = graph([stale_user(ELIGIBLE, 3)])
    elif path in CLOUD:
        body = cloud_body([], eligible, [cloud_user(ELIGIBLE)])
    else:
        body = sep_body([], eligible, [sep_user(ELIGIBLE, [P2])])
    if stats:
        body["paginationStats"] = {"roleEligibilityScheduleInstances": {"paginationTruncated": True}}
    return body


@pytest.mark.parametrize("path,key,mode", admin_params())
@pytest.mark.parametrize("case", sorted(TRUNCATED_ELIGIBILITY) + ["pagination_stats"])
def test_truncated_eligibility_read_is_incomplete(path, key, mode, case):
    body = truncated_body(path, case, stats=True) if case == "pagination_stats" else truncated_body(path, case)
    out = load(path, mode)(body)
    value = out["transformedResponse"][key]
    assert value is not True, (case, value)
    assert status(out) == "error", case
    assert any("eligible admins were not fully read" in e for e in info(out)["dataCollection"]["errors"]), case


@pytest.mark.parametrize("case", sorted(TRUNCATED_ELIGIBILITY))
def test_mfa_helper_treats_truncated_eligibility_as_not_read(case):
    spec = importlib.util.spec_from_file_location("pim_secadmins_trunc", MFA_SEC)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    accounts = module.admin_accounts(mfa_body(TRUNCATED_ELIGIBILITY[case]([ei(ELIGIBLE, role=SEC)])),
                                     module.SECURITY_ADMIN_ROLES, [])
    assert accounts["eligibleRead"] is False and accounts["eligibleIncomplete"] is True
    assert accounts["total"] == 1



# ============================================================================ second review of the follow-up
# The active read is judged by what it says, not by its shape: an absent or null roleAssignments beside an
# eligibility read is not evaluated whatever directoryRoles holds; a row with no roleDefinitionId cannot show
# which role it grants (it could hide a mailbox-licensed Global Administrator); a truncation marker the workflow
# set for the whole read (paginationTruncated, paginationStats.<read>) is honoured by every admin check; and a
# page list whose LAST page has no next link is a whole read, even though its earlier pages keep theirs.

@pytest.mark.parametrize("path,key,mode", admin_params())
@pytest.mark.parametrize("active", ["absent", "null"])
def test_missing_active_read_beside_a_broken_directory_role_read(path, key, mode, active):
    body = broken_active_body(path, "absent")
    if active == "null":
        body["roleAssignments"] = None
    body["directoryRoles"] = {"error": {"code": "Forbidden", "message": "placeholder"}}
    out = load(path, mode)(body)
    assert out["transformedResponse"][key] is not True and status(out) == "error"
    if path in STALE or path in CLOUD or path == SEP_RA:
        assert out["transformedResponse"][key] is None


NO_ROLE_CHECKS = [(SEP_AZURE, SEP_KEY), (SEP_M365, SEP_KEY), (SEP_RA, SEP_KEY), (CLOUD[0], CLOUD_KEY),
                  (CLOUD[1], CLOUD_KEY)]


@pytest.mark.parametrize("path,key", NO_ROLE_CHECKS)
@pytest.mark.parametrize("mode", ["native", "sandbox"])
def test_active_row_without_role_id_is_not_evaluated(path, key, mode):
    # The row hides a Global Administrator who holds a mailbox licence (or is synced from on-premises).
    hidden = {"id": "ra-hidden", "principalId": OTHER, "directoryScopeId": "/",
              "principal": {"@odata.type": USER_T, "id": OTHER}}
    if path in CLOUD:
        body = cloud_body([], graph([ei(ELIGIBLE)]), [cloud_user(ELIGIBLE), cloud_user(OTHER, True)])
    else:
        body = sep_body([], graph([ei(ELIGIBLE)]), [sep_user(ELIGIBLE, [P2]), sep_user(OTHER, [E3])])
    body["roleAssignments"] = graph([hidden])
    out = load(path, mode)(body)
    assert out["transformedResponse"][key] is not True and status(out) == "error"


WORKFLOW_MARKERS = {
    "workflow_flag": {"paginationTruncated": True},
    "workflow_metadata": {"response_metadata": {"paginationTruncated": "true"}},
    "stats_roleAssignments": {"paginationStats": {"roleAssignments": {"paginationTruncated": True}}},
    "stats_users": {"paginationStats": {"users": {"paginationTruncated": True}}},
}


@pytest.mark.parametrize("path,key,mode", admin_params())
@pytest.mark.parametrize("case", sorted(WORKFLOW_MARKERS))
def test_workflow_truncation_marker_is_honoured(path, key, mode, case):
    body = broken_active_body(path, "absent")
    body["roleAssignments"] = graph([])
    body.update(copy.deepcopy(WORKFLOW_MARKERS[case]))
    out = load(path, mode)(body)
    assert out["transformedResponse"][key] is not True and status(out) == "error", case


def full_page_list_body(path, last_link):
    """Active and eligibility reads as page lists whose earlier pages keep @odata.nextLink."""
    active = [graph([ra(ACTIVE)], **{"@odata.nextLink": NEXT}), graph([], **({"@odata.nextLink": NEXT} if last_link else {}))]
    eligible = [graph([ei(ELIGIBLE)], **{"@odata.nextLink": NEXT}), graph([])]
    if path in STALE:
        body = stale_body([], eligible)
        body["users"] = graph([stale_user(ACTIVE, 3), stale_user(ELIGIBLE, 3)])
    elif path in CLOUD:
        body = cloud_body([], eligible, [cloud_user(ACTIVE), cloud_user(ELIGIBLE)])
    else:
        body = sep_body([], eligible, [sep_user(ACTIVE, [P2]), sep_user(ELIGIBLE, [P2])])
    body["roleAssignments"] = active
    return body


@pytest.mark.parametrize("path,key,mode", admin_params())
def test_fully_read_page_list_is_whole(path, key, mode):
    out = load(path, mode)(full_page_list_body(path, last_link=False))
    expected = 0 if path in STALE else True
    assert out["transformedResponse"][key] == expected and status(out) == "success"
    assert out["transformedResponse"]["activeAdminCount"] == 1 and out["transformedResponse"]["eligibleAdminCount"] == 1


@pytest.mark.parametrize("path,key,mode", admin_params())
def test_page_list_whose_last_page_links_on_is_truncated(path, key, mode):
    out = load(path, mode)(full_page_list_body(path, last_link=True))
    assert out["transformedResponse"][key] is not True and status(out) == "error"
