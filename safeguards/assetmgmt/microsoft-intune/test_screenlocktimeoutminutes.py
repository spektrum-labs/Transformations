"""Intune screenLockTimeoutMinutes (EP-005): fixtures follow Microsoft Graph v1.0
deviceConfigurations with $expand=assignments (windows10GeneralConfiguration, windows10EndpointProtectionConfiguration,
deviceConfigurationAssignment targets). Names and ids are synthetic. Cases run typed, stringified (as Token-Service
stores it), wrapped, as a JSON string, and through the RestrictedPython replica."""
import importlib.util
import json
import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
FILE = os.path.join(HERE, "screenlocktimeoutminutes.py")
KEY = "screenLockTimeoutMinutes"


def load_plain():
    spec = importlib.util.spec_from_file_location("intune_screen_lock", FILE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def load_sandboxed():
    pytest.importorskip("RestrictedPython")
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import restricted_sandbox
    with open(FILE) as fh:
        return restricted_sandbox.load(fh.read())["transform"]


def value(body, loader=load_plain):
    out = loader()(body)
    return out["transformedResponse"][KEY], out


ALL_DEVICES = {"@odata.type": "#microsoft.graph.allDevicesAssignmentTarget",
               "deviceAndAppManagementAssignmentFilterId": None, "deviceAndAppManagementAssignmentFilterType": "none"}
ALL_USERS = {"@odata.type": "#microsoft.graph.allLicensedUsersAssignmentTarget",
             "deviceAndAppManagementAssignmentFilterId": None, "deviceAndAppManagementAssignmentFilterType": "none"}


def group(gid, exclude=False):
    return {"@odata.type": "#microsoft.graph." + ("exclusionGroupAssignmentTarget" if exclude else "groupAssignmentTarget"),
            "groupId": gid, "deviceAndAppManagementAssignmentFilterId": None,
            "deviceAndAppManagementAssignmentFilterType": "none"}


def general(name, mins, targets):
    return {"@odata.type": "#microsoft.graph.windows10GeneralConfiguration", "id": "cfg-" + name, "displayName": name,
            "passwordRequired": True, "passwordMinutesOfInactivityBeforeScreenTimeout": mins,
            "assignments": [{"id": "a-%d" % i, "target": t} for i, t in enumerate(targets)]}


def protection(name, mins, targets, field="localSecurityOptionsMachineInactivityLimit"):
    p = {"@odata.type": "#microsoft.graph.windows10EndpointProtectionConfiguration", "id": "cfg-" + name,
         "displayName": name, "localSecurityOptionsMachineInactivityLimit": None,
         "localSecurityOptionsMachineInactivityLimitInMinutes": None,
         "assignments": [{"id": "a-%d" % i, "target": t} for i, t in enumerate(targets)]}
    p[field] = mins
    return p


def graph(items, next_link=None):
    body = {"@odata.context": "https://graph.microsoft.com/v1.0/$metadata#deviceManagement/deviceConfigurations",
            "value": items}
    if next_link:
        body["@odata.nextLink"] = next_link
    return body


OTHER = {"@odata.type": "#microsoft.graph.iosGeneralDeviceConfiguration", "id": "cfg-ios", "displayName": "iOS",
         "passcodeMinutesOfInactivityBeforeScreenTimeout": 60, "assignments": [{"id": "a", "target": ALL_DEVICES}]}

PASSING = graph([general("Windows baseline", 10, [ALL_DEVICES]), protection("EP lock", 15, [ALL_USERS]), OTHER,
                 general("Finance", 5, [group("g-finance")])])
FAILING = graph([general("Windows baseline", 10, [ALL_DEVICES]),
                 protection("Legacy EP", 30, [ALL_DEVICES], "localSecurityOptionsMachineInactivityLimitInMinutes")])


def stringify(v):
    if isinstance(v, dict):
        return {k: stringify(x) for k, x in v.items()}
    if isinstance(v, list):
        return [stringify(x) for x in v]
    return str(v)


def ts_wrap(body):
    return {"data": {"apiResponse": body}, "validation": {"status": "skipped", "errors": [], "warnings": []}}


@pytest.mark.parametrize("loader", [load_plain, load_sandboxed])
@pytest.mark.parametrize("form", ["typed", "stringified", "wrapped", "json-string"])
def test_pass_and_fail(form, loader):
    good, bad = PASSING, FAILING
    if form == "stringified":
        good, bad = stringify(good), stringify(bad)
    if form == "wrapped":
        good, bad = ts_wrap(good), ts_wrap(bad)
    if form == "json-string":
        good, bad = json.dumps(good), json.dumps(bad)
    got, out = value(good, loader)
    assert got == 15
    assert "EP lock (15 min)" in out["additionalInfo"]["evaluation"]["passReasons"][0]
    got, out = value(bad, loader)
    assert got == 30
    assert "Legacy EP (30 min)" in out["additionalInfo"]["evaluation"]["failReasons"][0]


def test_narrowed_profiles_are_not_estate_wide():
    assert value(graph([general("x", 5, [ALL_DEVICES, group("g1", exclude=True)])]))[0] is None
    filtered = dict(ALL_DEVICES, deviceAndAppManagementAssignmentFilterId="f-1",
                    deviceAndAppManagementAssignmentFilterType="include")
    assert value(graph([general("x", 5, [filtered])]))[0] is None
    assert value(graph([general("x", 5, [group("g1")])]))[0] is None
    # a narrower profile with a longer limit is the limit its devices may get: it sets the value
    got, out = value(graph([general("short", 5, [ALL_DEVICES]), general("Kiosks", 60, [group("g1")])]))
    assert got == 60
    assert "Kiosks [assigned to groups only] (60 min)" in out["additionalInfo"]["evaluation"]["failReasons"][0]
    # a shorter narrower limit does not lower the estate-wide one
    assert value(graph([general("base", 12, [ALL_DEVICES]), general("Finance", 5, [group("g1")])]))[0] == 12
    # an unassigned profile is named as such
    out = value(graph([general("base", 12, [ALL_DEVICES]), general("draft", 90, [])]))[1]
    assert "draft (90 min, not assigned)" in out["additionalInfo"]["transformation"]["inputSummary"]["narrowerProfiles"]


def test_not_configured_values_are_ignored():
    assert value(graph([general("x", None, [ALL_DEVICES]), general("y", 0, [ALL_DEVICES])]))[0] is None
    assert value(graph([general("x", None, [ALL_DEVICES]), general("y", 12, [ALL_DEVICES])]))[0] == 12


def test_unreadable_assignments_are_not_evaluated():
    p = general("x", 10, [ALL_DEVICES])
    del p["assignments"]
    assert value(graph([p]))[0] is None


def test_truncated_read_is_not_evaluated():
    assert value(graph([general("x", 10, [ALL_DEVICES])], "https://graph.microsoft.com/v1.0/next"))[0] is None
    body = graph([general("x", 10, [ALL_DEVICES])])
    body["paginationTruncated"] = True
    assert value(body)[0] is None


NO_EVIDENCE = [
    {}, None, "", "{}", "not json",
    {"error": {"type": "authentication_error", "message": "invalid credentials"}},
    {"statusCode": 401, "error": "Unauthorized"},
    {"status_code": 401, "error": "Unauthorized"},
    {"error": {"statusCode": 401, "message": "Unauthorized"}},
    {"statusCode": 403, "error": "Forbidden"},
    {"error": {"code": "Forbidden", "message": "Application is not authorized to perform this operation."}},
    {"hello": "world"},
    {"foo": {"bar": [1, 2, 3]}},
    {"value": []},
    graph([OTHER]),
]


@pytest.mark.parametrize("body", NO_EVIDENCE)
def test_no_evidence_is_not_evaluated(body):
    for wrapped in (body, ts_wrap(body)):
        got, out = value(wrapped)
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


def test_except_path_is_not_evaluated():
    got, out = value(Poisoned())
    assert got is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"


def test_key_is_new_and_no_existing_transform_emits_it():
    seen = []
    for dirpath, dirnames, filenames in os.walk(os.path.join(ROOT, "safeguards")):
        for fn in filenames:
            path = os.path.join(dirpath, fn)
            if not fn.endswith(".py") or fn.startswith("test_") or path == FILE:
                continue
            with open(path, encoding="utf-8", errors="replace") as fh:
                if '"' + KEY + '"' in fh.read():
                    seen.append(path)
    assert seen == []


def test_device_restriction_limit_needs_a_required_password():
    p = general("no password", 10, [ALL_DEVICES])
    p["passwordRequired"] = False
    got, out = value(graph([p]))
    assert got is None
    assert "no password" in out["additionalInfo"]["evaluation"]["failReasons"][0]
    assert value(stringify(graph([p])))[0] is None
    # the endpoint protection setting is not password-gated
    assert value(graph([p, protection("EP", 10, [ALL_DEVICES])]))[0] == 10


@pytest.mark.parametrize("raw", ["abc", "nan", "-5", "1e400", True])
def test_unreadable_minutes_are_not_evaluated(raw):
    assert value(graph([general("odd", raw, [ALL_DEVICES]), general("ok", 10, [ALL_DEVICES])]))[0] is None


def test_fractional_minutes_round_up():
    assert value(graph([general("frac", "15.2", [ALL_DEVICES])]))[0] == 16
