"""ThreatLocker (69b438a1): isDefaultDenyApplicationControlEnabled from getComputers
(POST /portalapi/Computer/ComputerGetByAllParameters, IS-merged pages). SYNTHETIC fixtures only.

The rows carry the field set ThreatLocker returns for a computer (names, hostnames, ids and addresses below are
made up). Token-Service stores every leaf as a string, so each case also runs on a stringified copy, and each
case runs as plain Python and in the Token-Service sandbox replica.

True only when every current computer is in Secure Mode with no maintenance mode; False when any is not;
not evaluated (None, dataCollection "error") for an empty, error, partial or unreadable read.
"""
import copy
import importlib.util
import json
import pathlib
from datetime import datetime, timedelta

import pytest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]
NAME = "isDefaultDenyApplicationControlEnabled"
KEY = NAME

TAG = "tldefaultdeny"
try:
    import RestrictedPython  # noqa: F401
    spec = importlib.util.spec_from_file_location("restricted_sandbox_" + TAG, ROOT / "tools" / "restricted_sandbox.py")
    sandbox = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sandbox)
    load_code = sandbox.load
except ImportError:
    # without RestrictedPython the "sandbox" leg runs as plain exec (CI installs requirements-test.txt,
    # which carries RestrictedPython, so CI runs the real sandbox)
    def load_code(code, filename):
        ns = {"__name__": TAG + "_sandbox"}
        exec(compile(code, filename, "exec"), ns)
        return ns

MODES = ["python", "sandbox"]


def load(mode):
    path = HERE / (NAME + ".py")
    if mode == "sandbox":
        return load_code(path.read_text(), "<transformation>")["transform"]
    spec = importlib.util.spec_from_file_location(TAG + "_" + NAME, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.transform


def run(body, mode):
    out = load(mode)(copy.deepcopy(body))
    return out["transformedResponse"].get(KEY), out["additionalInfo"]["dataCollection"]["status"], out


def ts(body):
    return {"data": body, "validation": {"status": "skipped", "errors": [], "warnings": []}}


def iso(days_ago):
    return (datetime.utcnow() - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def computer(i, total, mode="Secure", days=0, deleted=False, maint=0, active_maint=None):
    """One ComputerGetByAllParameters row with ThreatLocker's field set (synthetic values)."""
    learning = mode != "Secure"
    return {
        "action": mode, "application": "", "appliesToType": "", "computerGroupId": "00000000-0000-4000-8000-00000000g001",
        "computerId": "00000000-0000-4000-8000-" + str(i).zfill(12), "dateAdded": "2024-01-02T03:04:05Z",
        "dateCreated": None, "driverStatusString": "Active", "group": "Workstations", "hostname": "HOST" + str(i),
        "installDate": None, "lastCheckin": iso(days), "lastCheckinIPAddress": "192.0.2." + str(i % 250 + 1),
        "computerName": "HOST" + str(i), "operatingSystem": "Windows 11 Enterprise", "organization": "Example Org",
        "organizationId": "00000000-0000-4000-8000-0000000000aa", "osType": 1,
        "threatLockerVersion": "10.12.18.4926", "threatLockerVersionId": "00000000-0000-4000-8000-0000000000bb",
        "newThreatLockerVersion": "", "serviceVersion": "10.12.18.4926", "uploadBaseFile": False,
        "restartComputerNeeded": False, "shouldRestart": False, "serialNumber": "SN" + str(i),
        "maintenanceTypeId": maint, "startDateTime": None, "isTamperProtectionDisabled": False,
        "isLearningMoreThanFourDays": False, "mode": mode, "versionMajor": 10, "versionMinor": 12,
        "isLockDownMode": False, "isOpsAlertsDisabled": False, "isIsolationMode": False, "progressBarLearning": 0,
        "isLearningModeMoreThanSeven": False, "isLearningModeLongerThanFiveYears": False, "maintenanceEndDate": None,
        "ipOperatingSystem": "", "hasComputerPassword": False, "hasAtLeastOneCheckin": True,
        "hasInstalationAtLeastSevenDaysAgo": True, "isReadyToSecure": learning, "isNeededReview": False,
        "hasZeroDeniesFourDays": False, "lastCheckinLocalIPAddresses": ["10.0.0." + str(i % 250 + 1)],
        "denyCountOneDay": 0, "denyCountSevenDays": 0, "denyCountThreeDays": 0, "totalRows": total,
        "isInheritFromGroup": True, "hasUnknownVersion": False, "isIsolated": False, "isLockedOut": False,
        "hasConfigManagerProduct": False, "maintenenceBannerIds": [], "targetThreatLockerVersion": "",
        "isDeleted": deleted, "username": "user" + str(i), "fullCheckinDateTime": iso(days),
        "fullCheckinMemoryUsage": "0", "fullCheckinIPAddress": "192.0.2." + str(i % 250 + 1), "isElevated": False,
        "activeMaintenanceModes": active_maint or [], "appControlLearningModeActive": learning,
        "maintenanceTicketRequiredParameter": "",
        "maintenanceCapabilities": {"applicationControl": True, "networkControl": True, "storageControl": True,
                                    "elevation": True, "tamper": True, "detect": False},
    }


def fleet(n, **kw):
    return [computer(i, n, **kw) for i in range(n)]


def stringify(rows):
    """Token-Service's stored shape: every scalar leaf a string (None as "None")."""
    def s(v):
        if isinstance(v, dict):
            return {k: s(x) for k, x in v.items()}
        if isinstance(v, list):
            return [s(x) for x in v]
        return str(v)
    return s(rows)


SHAPES = [lambda b: b, ts, lambda b: {"result": b}, lambda b: json.dumps(b), lambda b: stringify(b),
          lambda b: ts(stringify(b))]

NO_EVIDENCE = [None, {}, [], "", "[]", {"error": True, "statusCode": 403, "message": "Forbidden"},
               {"errors": [{"code": 4030010, "title": "Insufficient permissions"}]},
               {"error": True, "statusCode": 412, "message": "Required integration credentials are not connected"},
               {"statusCode": 500, "body": "upstream error"}]


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("shape", SHAPES)
def test_every_computer_secure_is_true(mode, shape):
    v, dc, out = run(shape(fleet(4)), mode)
    assert (v, dc) == (True, "success")
    assert out["transformedResponse"]["enforcingComputers"] == 4
    assert out["transformedResponse"]["judgedComputers"] == 4
    assert out["additionalInfo"]["evaluation"]["passReasons"]


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("bad", [
    {"mode": "Application Control Learning Mode", "maintenanceTypeId": 3},
    {"mode": "Installation Mode", "maintenanceTypeId": 2},
    {"mode": "Monitor Only"},
    {"activeMaintenanceModes": [{"maintenanceTypeId": 1, "maintenanceEndDate": "2099-01-01T00:00:00Z"}]},
    {"maintenanceTypeId": 3},
])
def test_one_computer_not_default_deny_is_false(mode, shape, bad):
    rows = fleet(4)
    rows[2].update(bad)
    v, dc, out = run(shape(rows), mode)
    assert (v, dc) == (False, "success")
    assert out["transformedResponse"]["enforcingComputers"] == 3
    reasons = out["additionalInfo"]["evaluation"]["failReasons"]
    assert reasons and "HOST2" in reasons[0]
    assert out["additionalInfo"]["dataCollection"]["errors"] == []


@pytest.mark.parametrize("mode", MODES)
def test_stale_and_deleted_computers_are_not_judged(mode):
    rows = fleet(4)
    rows[1].update(mode="Application Control Learning Mode", lastCheckin=iso(40))
    rows[3].update(mode="Monitor Only", isDeleted=True)
    v, dc, out = run(rows, mode)
    assert (v, dc) == (True, "success")
    assert out["transformedResponse"]["staleComputerCount"] == 1
    assert out["transformedResponse"]["judgedComputers"] == 2


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("body", [
    fleet(3)[:2],                                          # page 1 of a larger organisation
    fleet(600)[:500],                                      # the single 500-row page, more pages remain
    [dict(computer(1, 1), totalRows=None)],
    [dict(computer(1, 1), totalRows="many")],
    [dict(computer(1, 1), computerId="")],
    fleet(2, days=40),                                     # nobody checked in within the window
    [dict(computer(0, 2), mode=None), computer(1, 2)],     # a judged computer without a mode
    [dict(computer(0, 2), mode=""), computer(1, 2)],
] + NO_EVIDENCE)
def test_partial_or_no_evidence_is_unevaluated(mode, body):
    for b in (body, ts(body)):
        v, dc, out = run(b, mode)
        assert (v, dc) == (None, "error"), b if not isinstance(b, list) else len(b)
        assert out["additionalInfo"]["dataCollection"]["errors"]


@pytest.mark.parametrize("mode", MODES)
def test_partial_read_never_passes_even_when_every_row_read_is_secure(mode):
    rows = fleet(1000)[:500]
    v, dc, out = run(rows, mode)
    assert (v, dc) == (None, "error")
    assert "500 of 1000" in out["additionalInfo"]["dataCollection"]["errors"][0]


@pytest.mark.parametrize("mode", MODES)
def test_partial_read_with_a_bad_row_is_still_unevaluated(mode):
    rows = fleet(10)[:5]
    rows[0]["mode"] = "Application Control Learning Mode"
    assert run(rows, mode)[:2] == (None, "error")


@pytest.mark.parametrize("mode", MODES)
def test_duplicate_rows_do_not_complete_a_partial_read(mode):
    rows = fleet(4)[:2]
    rows = rows + copy.deepcopy(rows)
    assert run(rows, mode)[:2] == (None, "error")
