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


# ---- areServiceAccountsInteractiveSignInBlocked -----------------------------------------------------------------

G_SVC = "00000000-0000-0000-0000-0000000000a1"
G_SVC2 = "00000000-0000-0000-0000-0000000000a2"
G_STAFF = "00000000-0000-0000-0000-0000000000b1"


def ca(name, groups=(), all_users=False, state="enabled", block=True, apps=("All",), exclude_groups=(),
       client_types=("all",), locations=None):
    cond = {"users": {"includeUsers": ["All"] if all_users else [], "excludeUsers": [], "includeGroups": list(groups),
                      "excludeGroups": list(exclude_groups), "includeRoles": [], "excludeRoles": []},
            "applications": {"includeApplications": list(apps), "excludeApplications": []},
            "clientAppTypes": list(client_types), "locations": locations, "platforms": None,
            "signInRiskLevels": [], "userRiskLevels": []}
    return {"id": "pol-" + name, "displayName": name, "state": state, "conditions": cond,
            "grantControls": {"operator": "OR", "builtInControls": ["block"] if block else ["mfa"]}}


def groups(extra=()):
    return graph([{"id": G_SVC, "displayName": "SG-Service-Accounts", "groupTypes": []},
                  {"id": G_SVC2, "displayName": "svc-integrations", "groupTypes": []},
                  {"id": G_STAFF, "displayName": "All Staff", "groupTypes": []}] + list(extra))


def svc_body(policies, grp=None):
    return {"conditionalAccessPolicies": graph(policies), "groups": grp or groups()}


SVC_PASS = svc_body([ca("Block service accounts", groups=[G_SVC, G_SVC2]), ca("MFA all", all_users=True, block=False)])
SVC_FAIL = svc_body([ca("Block svc", groups=[G_SVC]),
                     ca("Block integrations outside office", groups=[G_SVC2],
                        locations={"includeLocations": ["All"], "excludeLocations": ["AllTrusted"]})])


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
    assert "SG-Service-Accounts" in out["additionalInfo"]["evaluation"]["passReasons"][0]
    got, out = value(SVC, bad, loader)
    assert got is False
    reason = out["additionalInfo"]["evaluation"]["failReasons"][0]
    assert "svc-integrations" in reason and "narrowed by locations" in reason


def test_report_only_excluded_and_partial_blocks_do_not_count():
    assert value(SVC, svc_body([ca("ro", groups=[G_SVC, G_SVC2], state="enabledForReportingButNotEnforced")]))[0] is False
    assert value(SVC, svc_body([ca("all", all_users=True, exclude_groups=[G_SVC2]), ca("g1", groups=[G_SVC])]))[0] is False
    # an All-users block that carves out another group may let members of this group through: not counted
    assert value(SVC, svc_body([ca("all", all_users=True, exclude_groups=[G_SVC2]), ca("g2", groups=[G_SVC2])]))[0] is False
    assert value(SVC, svc_body([ca("g1", groups=[G_SVC]), ca("g2", groups=[G_SVC2])]))[0] is True
    assert value(SVC, svc_body([ca("apps", groups=[G_SVC, G_SVC2], apps=("app-1",))]))[0] is False
    assert value(SVC, svc_body([ca("browser", groups=[G_SVC, G_SVC2], client_types=("browser",))]))[0] is False
    assert value(SVC, svc_body([]))[0] is False


def test_no_service_account_group_is_not_evaluated():
    got, out = value(SVC, svc_body([ca("b", all_users=True)], graph([{"id": G_STAFF, "displayName": "Service Desk"}])))
    assert got is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"


@pytest.mark.parametrize("name,expected", [
    ("SG-Service-Accounts", True), ("svc-backup", True), ("Non-Interactive Accounts", True), ("ServiceAccounts", True),
    ("Service Desk", False), ("Customer Service", False), ("Services Team", False), ("svchost admins", False),
])
def test_service_group_marker(name, expected):
    spec = importlib.util.spec_from_file_location("svc_marker", os.path.join(HERE, SVC + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.is_service_group(name) is expected


def test_service_accounts_truncated_parts_are_not_evaluated():
    body = svc_body([ca("b", groups=[G_SVC, G_SVC2])])
    body["groups"]["@odata.nextLink"] = "https://graph.microsoft.com/v1.0/groups?$skiptoken=x"
    assert value(SVC, body)[0] is None
    body = svc_body([ca("b", groups=[G_SVC, G_SVC2])])
    body["conditionalAccessPolicies"]["paginationTruncated"] = True
    assert value(SVC, body)[0] is None
    body = svc_body([ca("b", groups=[G_SVC, G_SVC2])])
    body["groups"] = {"error": {"code": "Authorization_RequestDenied", "message": "Insufficient privileges"}}
    assert value(SVC, body)[0] is None
    body = svc_body([ca("b", groups=[G_SVC, G_SVC2])])
    del body["groups"]
    assert value(SVC, body)[0] is None


# ---- lapsCoveragePercentage --------------------------------------------------------------------------------------

def ago(days):
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat().replace("+00:00", "Z")


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
    assert got == round(18 * 100.0 / 21, 2)
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


@pytest.mark.parametrize("carve_out", [
    {"excludeUsers": ["00000000-0000-0000-0000-0000000000c1"]},
    {"excludeRoles": ["62e90394-69f5-4237-9190-012177145e10"]},
    {"excludeGroups": [G_STAFF]},
    {"excludeGuestsOrExternalUsers": {"guestOrExternalUserTypes": "internalGuest", "externalTenants": {"membershipKind": "all"}}},
])
def test_any_user_side_carve_out_is_not_a_full_block(carve_out):
    pol = with_users(ca("Block svc", groups=[G_SVC, G_SVC2]), **carve_out)
    got, out = value(SVC, svc_body([pol]))
    assert got is False
    assert "narrowed by excludes" in out["additionalInfo"]["evaluation"]["failReasons"][0]


def test_application_filter_and_unknown_conditions_narrow_the_block():
    pol = ca("Block svc", groups=[G_SVC, G_SVC2])
    pol["conditions"]["applications"]["applicationFilter"] = {"mode": "exclude", "rule": "CustomSecurityAttribute.x -eq \"y\""}
    assert value(SVC, svc_body([pol]))[0] is False
    pol = ca("Block svc", groups=[G_SVC, G_SVC2])
    pol["conditions"]["insiderRiskLevels"] = "elevated"
    got, out = value(SVC, svc_body([pol]))
    assert got is False and "insiderRiskLevels" in out["additionalInfo"]["evaluation"]["failReasons"][0]
    pol = ca("Block svc", groups=[G_SVC, G_SVC2])
    pol["conditions"]["someFutureCondition"] = {"mode": "include"}
    assert value(SVC, svc_body([pol]))[0] is False
    # empty or null conditions do not narrow
    pol = ca("Block svc", groups=[G_SVC, G_SVC2])
    pol["conditions"].update({"devices": None, "authenticationFlows": None, "insiderRiskLevels": None,
                              "servicePrincipalRiskLevels": []})
    assert value(SVC, svc_body([pol]))[0] is True
    assert value(SVC, stringify(svc_body([pol])))[0] is True


def test_disabled_policy_is_named_as_disabled_not_report_only():
    got, out = value(SVC, svc_body([ca("Off", groups=[G_SVC, G_SVC2], state="disabled")]))
    assert got is False
    assert "state disabled" in out["additionalInfo"]["evaluation"]["failReasons"][0]


def test_laps_rotation_overdue_does_not_count():
    overdue = cred(2)
    overdue["lastBackupDateTime"] = ago(400)
    overdue["refreshDateTime"] = ago(370)
    old_no_refresh = cred(3)
    old_no_refresh["lastBackupDateTime"] = ago(400)
    old_no_refresh["refreshDateTime"] = None
    got, out = value(LAPS, laps_body([device(1), device(2), device(3)], [cred(1), overdue, old_no_refresh]))
    assert got == round(100.0 / 3, 2)
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


@pytest.mark.parametrize("name,keys", [(SVC, ("conditionalAccessPolicies", "groups")),
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
