"""Entra ID One-Click checks: areServiceAccountsInteractiveSignInBlocked (IAM-001) and
lapsCoveragePercentage (IAM-005). Fixtures follow Microsoft Graph v1.0 shapes (conditionalAccessPolicy, group,
deviceLocalCredentialInfo, device) as merged by each new workflow. Ids are synthetic GUIDs, names are synthetic.
Cases run typed, stringified (as Token-Service stores it), wrapped, as a JSON string, and through the
RestrictedPython replica."""
import importlib.util
import json
import os
import sys
from datetime import datetime, timedelta, timezone

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
SVC = "areserviceaccountsinteractivesigninblocked"
LAPS = "lapscoveragepercentage"
KEYS = {SVC: "areServiceAccountsInteractiveSignInBlocked", LAPS: "lapsCoveragePercentage"}


def load_plain(name):
    spec = importlib.util.spec_from_file_location("entra_p1_" + name, os.path.join(HERE, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def load_sandboxed(name):
    pytest.importorskip("RestrictedPython")
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import restricted_sandbox
    with open(os.path.join(HERE, name + ".py")) as fh:
        return restricted_sandbox.load(fh.read())["transform"]


def value(name, body, loader=load_plain):
    out = loader(name)(body)
    return out["transformedResponse"][KEYS[name]], out


def graph(items, next_link=None):
    body = {"@odata.context": "https://graph.microsoft.com/v1.0/$metadata#x", "value": items}
    if next_link:
        body["@odata.nextLink"] = next_link
    return body


def stringify(v):
    if isinstance(v, dict):
        return {k: stringify(x) for k, x in v.items()}
    if isinstance(v, list):
        return [stringify(x) for x in v]
    return str(v)


def ts_wrap(body):
    return {"data": {"apiResponse": body}, "validation": {"status": "skipped", "errors": [], "warnings": []}}


def ago(days):
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat().replace("+00:00", "Z")


# ---- areServiceAccountsInteractiveSignInBlocked -----------------------------------------------------------------
# WI-3c (16 Nov 2026): service accounts by signal. SA1/SA2 have only non-interactive sign-ins in 90 days; HUMAN
# signs in interactively. G_SVC/G_SVC2/G_STAFF are read whole (transitive members), paired by position.

G_SVC = "00000000-0000-0000-0000-0000000000a1"
G_SVC2 = "00000000-0000-0000-0000-0000000000a2"
G_STAFF = "00000000-0000-0000-0000-0000000000b1"
SA1 = "5a000000-0000-0000-0000-000000000001"
SA2 = "5a000000-0000-0000-0000-000000000002"
HUMAN = "5b000000-0000-0000-0000-000000000003"
BG1 = "5c000000-0000-0000-0000-000000000004"
BG2 = "5c000000-0000-0000-0000-000000000005"
BG3 = "5c000000-0000-0000-0000-000000000006"


def ca(name, groups=(), all_users=False, state="enabled", block=True, apps=("All",), exclude_groups=(),
       client_types=("all",), locations=None, include_users=(), exclude_users=()):
    cond = {"users": {"includeUsers": ["All"] if all_users else list(include_users), "excludeUsers": list(exclude_users),
                      "includeGroups": list(groups), "excludeGroups": list(exclude_groups), "includeRoles": [],
                      "excludeRoles": []},
            "applications": {"includeApplications": list(apps), "excludeApplications": []},
            "clientAppTypes": list(client_types), "locations": locations, "platforms": None,
            "signInRiskLevels": [], "userRiskLevels": []}
    return {"id": "pol-" + name, "displayName": name, "state": state, "conditions": cond,
            "grantControls": {"operator": "OR", "builtInControls": ["block"] if block else ["mfa"]}}


def account(uid, interactive=None, background=None, enabled=True, kind="Member", activity=True):
    item = {"id": uid, "accountEnabled": enabled, "userType": kind}
    if activity:
        item["signInActivity"] = {"lastSignInDateTime": None if interactive is None else ago(interactive),
                                  "lastNonInteractiveSignInDateTime": None if background is None else ago(background)}
    return item


USERS = [account(SA1, interactive=200, background=1), account(SA2, background=3),
         account(HUMAN, interactive=1, background=1)]
MEMBERS = [(G_SVC, [SA1]), (G_SVC2, [SA2]), (G_STAFF, [HUMAN])]


def svc_body(policies, users=None, members=None):
    pairs = MEMBERS if members is None else members
    return {"conditionalAccessPolicies": graph(policies), "signInUsers": graph(USERS if users is None else users),
            "caPolicyGroups": {"groupIds": [{"id": g} for g, _ in pairs]},
            "groupMembers": [graph([{"id": m} for m in ids]) for _, ids in pairs]}


SVC_PASS = svc_body([ca("Block service accounts", groups=[G_SVC, G_SVC2]), ca("MFA all", all_users=True, block=False)])
SVC_FAIL = svc_body([ca("Block svc", groups=[G_SVC]),
                     ca("Block integrations outside office", groups=[G_SVC2],
                        locations={"includeLocations": ["All"], "excludeLocations": ["AllTrusted"]})])


def svc_reason(out, kind):
    return " ".join(out["additionalInfo"]["evaluation"][kind])


@pytest.mark.parametrize("loader", [load_plain, load_sandboxed])
@pytest.mark.parametrize("form", ["typed", "stringified", "wrapped", "json-string"])
def test_service_accounts_pass_and_fail(form, loader):
    good, bad = SVC_PASS, SVC_FAIL
    if form == "stringified":
        good, bad = stringify(good), stringify(bad)
    if form == "wrapped":
        good, bad = ts_wrap(good), ts_wrap(bad)
    if form == "json-string":
        good, bad = json.dumps(good), json.dumps(bad)
    got, out = value(SVC, good, loader)
    assert got is True
    assert "All 2 service account(s) are blocked" in svc_reason(out, "passReasons")
    got, out = value(SVC, bad, loader)
    assert got is False
    reason = svc_reason(out, "failReasons")
    assert "1 of 2 service account(s) are not blocked" in reason and "user 5a000000..." in reason
    assert SA2 not in reason


def test_human_with_interactive_sign_ins_is_not_a_service_account():
    got, out = value(SVC, svc_body([ca("Block svc", groups=[G_SVC, G_SVC2])]))
    assert got is True
    assert out["additionalInfo"]["transformation"]["inputSummary"]["serviceAccountsBySignInSignal"] == 2


@pytest.mark.parametrize("users", [[], [account(SA1, background=1, enabled=False)],
                                   [account(SA1, background=1, kind="Guest")]],
                         ids=["empty", "only-disabled", "only-guests"])
def test_no_enabled_member_account_read_is_not_evaluated(users):
    got, out = value(SVC, svc_body([ca("Block svc", groups=[G_SVC, G_SVC2])], users=users))
    assert got is None and "no enabled member account" in out["additionalInfo"]["dataCollection"]["errors"][0]


def test_disabled_guest_and_dormant_accounts_are_not_service_accounts():
    users = [account(SA1, background=1, enabled=False), account(SA2, background=1, kind="Guest"),
             account(HUMAN, background=120), account(BG1)]
    got, out = value(SVC, svc_body([], users=users))
    assert got is True
    assert "No service account found" in svc_reason(out, "passReasons")


def test_report_only_disabled_narrowed_and_excluding_blocks_do_not_count():
    for policies in ([ca("ro", groups=[G_SVC, G_SVC2], state="enabledForReportingButNotEnforced")],
                     [ca("off", groups=[G_SVC, G_SVC2], state="disabled")],
                     [ca("all but svc2", all_users=True, exclude_groups=[G_SVC2])],
                     [ca("all but sa2", all_users=True, exclude_users=[SA2])],
                     [ca("apps", groups=[G_SVC, G_SVC2], apps=("app-1",))],
                     [ca("browser", groups=[G_SVC, G_SVC2], client_types=("browser",))],
                     [ca("mfa only", groups=[G_SVC, G_SVC2], block=False)], []):
        assert value(SVC, svc_body(policies))[0] is False
    assert value(SVC, svc_body([ca("g1", groups=[G_SVC]), ca("g2", groups=[G_SVC2])]))[0] is True
    assert value(SVC, svc_body([ca("all", all_users=True, exclude_groups=[G_STAFF])]))[0] is True
    assert value(SVC, svc_body([ca("by id", include_users=[SA1, SA2])]))[0] is True


def test_mfa_carve_out_finds_service_accounts_beyond_break_glass():
    users = USERS + [account(BG1), account(BG2), account(BG3)]
    block = ca("Block svc", groups=[G_SVC, G_SVC2])
    two = ca("MFA all", all_users=True, block=False, exclude_users=[BG1, BG2])
    got, out = value(SVC, svc_body([block, two], users=users))
    assert got is True  # two excluded accounts: break-glass, not judged
    assert out["additionalInfo"]["transformation"]["inputSummary"]["breakGlassAccountsNotJudged"] == 2
    three = ca("MFA all", all_users=True, block=False, exclude_users=[BG1, BG2, BG3])
    got, out = value(SVC, svc_body([block, three], users=users))
    assert got is False
    assert "3 of 5 service account(s) are not blocked" in svc_reason(out, "failReasons")


def test_mfa_carve_out_through_a_read_group():
    users = USERS + [account(BG1), account(BG2), account(BG3)]
    members = MEMBERS + [("00000000-0000-0000-0000-0000000000c1", [BG1, BG2, BG3])]
    mfa = ca("MFA all", all_users=True, block=False, exclude_groups=["00000000-0000-0000-0000-0000000000c1"])
    got, _ = value(SVC, svc_body([ca("Block svc", groups=[G_SVC, G_SVC2]), mfa], users=users, members=members))
    assert got is False


def test_unread_group_keeps_it_not_evaluated_but_never_hides_a_failure():
    unread = MEMBERS[:1] + [(G_SVC2, None)] + MEMBERS[2:]
    body = svc_body([ca("Block svc", groups=[G_SVC, G_SVC2])], members=[(g, ids or []) for g, ids in unread])
    body["groupMembers"][1] = {"vendorErrorAsResponse": {"status": 403}}
    assert value(SVC, body)[0] is None
    body = svc_body([ca("Block sa2", include_users=[SA2], exclude_groups=[G_STAFF])], members=MEMBERS)
    body["groupMembers"][2] = {"error": {"code": "Request_ResourceNotFound"}}
    got, out = value(SVC, body)
    assert got is False  # SA1 is in no block policy at all, whatever the unread G_STAFF holds
    assert "1 of 2 service account(s)" in out["additionalInfo"]["evaluation"]["failReasons"][0]
    mfa = ca("MFA all", all_users=True, block=False, exclude_groups=["00000000-0000-0000-0000-0000000000c9"])
    got, out = value(SVC, svc_body([ca("Block svc", groups=[G_SVC, G_SVC2]), mfa]))
    assert got is None and "excluded from an MFA policy was not read" in out["additionalInfo"]["dataCollection"]["errors"][0]


def test_sign_in_read_without_activity_or_with_bad_dates_is_not_evaluated():
    no_activity = [account(SA1, activity=False), account(HUMAN, activity=False)]
    got, out = value(SVC, svc_body([], users=no_activity))
    assert got is None and "signInActivity" in out["additionalInfo"]["dataCollection"]["errors"][0]
    bad = [account(SA1), account(HUMAN)]
    bad[0]["signInActivity"]["lastNonInteractiveSignInDateTime"] = "11/01/2026 08:00"
    assert value(SVC, svc_body([], users=bad))[0] is None
    for broken in ({"error": {"code": "Authentication_RequestFromNonPremiumTenantOrB2CTenant"}},
                   {"stepError": True, "statusCode": 403}, None, [],
                   graph([account(SA1, background=1)], next_link="https://graph.microsoft.com/v1.0/users?$skiptoken=x")):
        body = svc_body([ca("Block svc", groups=[G_SVC, G_SVC2])])
        body["signInUsers"] = broken
        assert value(SVC, body)[0] is None


def test_service_accounts_truncated_parts_are_not_evaluated():
    body = svc_body([ca("b", groups=[G_SVC, G_SVC2])])
    body["conditionalAccessPolicies"]["paginationTruncated"] = True
    assert value(SVC, body)[0] is None
    body = svc_body([ca("b", groups=[G_SVC, G_SVC2])])
    body["conditionalAccessPolicies"] = {"error": {"code": "Authorization_RequestDenied", "message": "Insufficient"}}
    assert value(SVC, body)[0] is None
    body = svc_body([ca("b", groups=[G_SVC, G_SVC2])])
    del body["signInUsers"]
    assert value(SVC, body)[0] is None


def test_legacy_groups_part_is_ignored():
    body = dict(SVC_PASS, groups=graph([{"id": G_SVC, "displayName": "SG-Service-Accounts"}]))
    assert value(SVC, body)[0] is True


# ---- lapsCoveragePercentage --------------------------------------------------------------------------------------

def device(n, trust="AzureAd", enabled=True, seen_days=3):
    return {"id": "obj-%03d" % n, "deviceId": "00000000-0000-0000-0000-%012d" % n, "displayName": "WS-%03d" % n,
            "accountEnabled": enabled, "operatingSystem": "Windows", "trustType": trust,
            "approximateLastSignInDateTime": ago(seen_days)}


def cred(n):
    return {"id": "00000000-0000-0000-0000-%012d" % n, "deviceName": "WS-%03d" % n,
            "lastBackupDateTime": ago(1), "refreshDateTime": ago(-29)}


def laps_body(devices, creds):
    return {"deviceLocalCredentials": graph(creds), "windowsDevices": graph(devices)}


FLEET = [device(i) for i in range(1, 21)] + [device(21, trust="Workplace"), device(22, enabled=False),
                                             device(23, seen_days=200), device(24, trust="ServerAd")]
LAPS_PASS = laps_body(FLEET, [cred(i) for i in range(1, 21)] + [cred(24)])
LAPS_FAIL = laps_body(FLEET, [cred(i) for i in range(1, 19)])


@pytest.mark.parametrize("loader", [load_plain, load_sandboxed])
@pytest.mark.parametrize("form", ["typed", "stringified", "wrapped", "json-string"])
def test_laps_pass_and_fail(form, loader):
    good, bad = LAPS_PASS, LAPS_FAIL
    if form == "stringified":
        good, bad = stringify(good), stringify(bad)
    if form == "wrapped":
        good, bad = ts_wrap(good), ts_wrap(bad)
    if form == "json-string":
        good, bad = json.dumps(good), json.dumps(bad)
    got, out = value(LAPS, good, loader)
    assert got == 100.0
    assert out["additionalInfo"]["transformation"]["inputSummary"]["activeJoinedWindowsDevices"] == 21
    got, out = value(LAPS, bad, loader)
    assert got == (18 * 10000 // 21) / 100.0
    reason = out["additionalInfo"]["evaluation"]["failReasons"][0]
    assert "18 of 21" in reason and "WS-019" in reason and "WS-024" in reason


def test_laps_403_before_consent_is_not_evaluated():
    body = laps_body(FLEET, [])
    body["deviceLocalCredentials"] = {"error": {"code": "Authorization_RequestDenied",
                                                "message": "Missing role permissions on the request."}}
    got, out = value(LAPS, body)
    assert got is None
    assert "DeviceLocalCredential.ReadBasic.All" in out["additionalInfo"]["evaluation"]["recommendations"][0]


def test_laps_truncated_or_empty_population_is_not_evaluated():
    body = laps_body(FLEET, [cred(1)])
    body["windowsDevices"]["@odata.nextLink"] = "https://graph.microsoft.com/v1.0/devices?$skiptoken=x"
    assert value(LAPS, body)[0] is None
    assert value(LAPS, laps_body([device(1, trust="Workplace"), device(2, seen_days=400)], []))[0] is None
    assert value(LAPS, laps_body([], [cred(1)]))[0] is None


def test_laps_credential_without_backup_time_does_not_count():
    c = cred(1)
    c["lastBackupDateTime"] = None
    assert value(LAPS, laps_body([device(1)], [c]))[0] == 0.0


# ---- shared -------------------------------------------------------------------------------------------------------

NO_EVIDENCE = [
    {}, None, "", "{}", "not json",
    {"error": {"type": "authentication_error", "message": "invalid credentials"}},
    {"statusCode": 401, "error": "Unauthorized"},
    {"status_code": 401, "error": "Unauthorized"},
    {"error": {"statusCode": 401, "message": "Unauthorized"}},
    {"statusCode": 403, "error": "Forbidden"},
    {"error": {"code": "InvalidAuthenticationToken", "message": "Access token is empty."}},
    {"hello": "world"},
    {"foo": {"bar": [1, 2, 3]}},
    {"value": []},
    graph([]),
]


@pytest.mark.parametrize("name", [SVC, LAPS])
@pytest.mark.parametrize("body", NO_EVIDENCE)
def test_no_evidence_is_not_evaluated(name, body):
    for wrapped in (body, ts_wrap(body)):
        got, out = value(name, wrapped)
        assert got is None
        assert out["additionalInfo"]["dataCollection"]["status"] == "error"
        assert out["additionalInfo"]["dataCollection"]["errors"]


class Poisoned(dict):
    def __init__(self):
        super().__init__(poisoned=True)

    def boom(self, *args, **kwargs):
        raise RuntimeError("poisoned read")

    get = __getitem__ = __contains__ = keys = items = values = __iter__ = boom

    def __len__(self):
        return 1


@pytest.mark.parametrize("name", [SVC, LAPS])
def test_except_path_is_not_evaluated(name):
    got, out = value(name, Poisoned())
    assert got is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"


def test_keys_are_new_and_no_existing_transform_emits_them():
    ours = set(os.path.join(HERE, n + ".py") for n in KEYS)
    seen = []
    for dirpath, dirnames, filenames in os.walk(os.path.join(ROOT, "safeguards")):
        for fn in filenames:
            path = os.path.join(dirpath, fn)
            if not fn.endswith(".py") or fn.startswith("test_") or path in ours:
                continue
            with open(path, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
            for k in KEYS.values():
                if '"' + k + '"' in text:
                    seen.append((path, k))
    assert seen == []


def with_users(policy, **extra):
    policy["conditions"]["users"].update(extra)
    return policy


@pytest.mark.parametrize("carve_out,expected", [
    ({"excludeUsers": ["00000000-0000-0000-0000-0000000000c1"]}, True),   # another account: SA1/SA2 stay blocked
    ({"excludeUsers": [SA2]}, False),
    ({"excludeGroups": [G_STAFF]}, True),                                   # read whole, holds no service account
    ({"excludeGroups": [G_SVC2]}, False),
    ({"excludeRoles": ["62e90394-69f5-4237-9190-012177145e10"]}, None),     # role holders not read: may exclude
    ({"excludeGuestsOrExternalUsers": {"guestOrExternalUserTypes": "internalGuest",
                                       "externalTenants": {"membershipKind": "all"}}}, None),
])
def test_user_side_carve_outs_are_judged_per_account(carve_out, expected):
    pol = with_users(ca("Block svc", groups=[G_SVC, G_SVC2]), **carve_out)
    assert value(SVC, svc_body([pol]))[0] is expected


def test_application_filter_and_unknown_conditions_narrow_the_block():
    pol = ca("Block svc", groups=[G_SVC, G_SVC2])
    pol["conditions"]["applications"]["applicationFilter"] = {"mode": "exclude", "rule": "CustomSecurityAttribute.x -eq \"y\""}
    assert value(SVC, svc_body([pol]))[0] is False
    pol = ca("Block svc", groups=[G_SVC, G_SVC2])
    pol["conditions"]["insiderRiskLevels"] = "elevated"
    got, out = value(SVC, svc_body([pol]))
    assert got is False and "2 of 2 service account(s) are not blocked" in out["additionalInfo"]["evaluation"]["failReasons"][0]
    pol = ca("Block svc", groups=[G_SVC, G_SVC2])
    pol["conditions"]["someFutureCondition"] = {"mode": "include"}
    assert value(SVC, svc_body([pol]))[0] is False
    # empty or null conditions do not narrow
    pol = ca("Block svc", groups=[G_SVC, G_SVC2])
    pol["conditions"].update({"devices": None, "authenticationFlows": None, "insiderRiskLevels": None,
                              "servicePrincipalRiskLevels": []})
    assert value(SVC, svc_body([pol]))[0] is True
    assert value(SVC, stringify(svc_body([pol])))[0] is True


def test_disabled_policy_does_not_block():
    got, out = value(SVC, svc_body([ca("Off", groups=[G_SVC, G_SVC2], state="disabled")]))
    assert got is False


def test_laps_rotation_overdue_does_not_count():
    overdue = cred(2)
    overdue["lastBackupDateTime"] = ago(400)
    overdue["refreshDateTime"] = ago(370)
    old_no_refresh = cred(3)
    old_no_refresh["lastBackupDateTime"] = ago(400)
    old_no_refresh["refreshDateTime"] = None
    got, out = value(LAPS, laps_body([device(1), device(2), device(3)], [cred(1), overdue, old_no_refresh]))
    assert got == 33.33
    assert "WS-002 (rotation overdue)" in out["additionalInfo"]["evaluation"]["failReasons"][0]


def test_empty_condition_objects_do_not_narrow():
    pol = ca("Block svc", groups=[G_SVC, G_SVC2])
    pol["conditions"]["devices"] = {"includeDevices": [], "excludeDevices": [], "deviceFilter": None}
    pol["conditions"]["clientApplications"] = {"includeServicePrincipals": [], "excludeServicePrincipals": [],
                                              "servicePrincipalFilter": None}
    pol["conditions"]["applications"]["applicationFilter"] = None
    pol["conditions"]["users"]["excludeGuestsOrExternalUsers"] = None
    assert value(SVC, svc_body([pol]))[0] is True
    assert value(SVC, stringify(svc_body([pol])))[0] is True
    pol["conditions"]["devices"]["deviceFilter"] = {"mode": "exclude", "rule": "device.isCompliant -eq True"}
    assert value(SVC, svc_body([pol]))[0] is False


@pytest.mark.parametrize("name,keys", [(SVC, ("conditionalAccessPolicies", "signInUsers")),
                                       (LAPS, ("deviceLocalCredentials", "windowsDevices"))])
def test_workflow_reported_truncation_is_not_evaluated(name, keys):
    body = SVC_PASS if name == SVC else LAPS_PASS
    for k in keys:
        marked = dict(body, paginationTruncated=True, paginationStats={k: {"paginationTruncated": True}})
        assert value(name, marked)[0] is None
        assert value(name, stringify(marked))[0] is None
    assert value(name, dict(body, paginationStats={keys[0]: {"paginationTruncated": False}}))[0] is not None


def test_modern_client_types_only_leave_legacy_sign_in_open():
    pol = ca("Block svc", groups=[G_SVC, G_SVC2], client_types=("browser", "mobileAppsAndDesktopClients"))
    assert value(SVC, svc_body([pol]))[0] is False
    pol = ca("Block svc", groups=[G_SVC, G_SVC2],
             client_types=("browser", "mobileAppsAndDesktopClients", "exchangeActiveSync", "other"))
    assert value(SVC, svc_body([pol]))[0] is True


def test_laps_percentage_never_rounds_up_across_a_threshold():
    devices = [device(i) for i in range(1, 201)]
    creds = [cred(i) for i in range(1, 190)]          # 189 of 200 = 94.5%
    got = value(LAPS, laps_body(devices, creds))[0]
    assert got == 94.5
    devices = [device(i) for i in range(1, 2001)]
    creds = [cred(i) for i in range(1, 1900)]          # 1899 of 2000 = 94.95%
    assert value(LAPS, laps_body(devices, creds))[0] == 94.95
    # 2 of 3 = 66.666...: round() would give 66.67, truncation gives 66.66
    assert value(LAPS, laps_body([device(1), device(2), device(3)], [cred(1), cred(2)]))[0] == 66.66
    # 1999 of 2001 = 99.9000...; 3998 of 4001 = 99.925...: round() 99.93, truncation 99.92
    devices = [device(i) for i in range(1, 4002)]
    assert value(LAPS, laps_body(devices, [cred(i) for i in range(1, 3999)]))[0] == 99.92
