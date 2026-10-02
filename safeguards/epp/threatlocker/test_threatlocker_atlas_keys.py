"""ThreatLocker (69b438a1): isEPPDeployed, requiredCoveragePercentage and isEPPConfigured from
getComputers (POST /portalapi/Computer/ComputerGetByAllParameters, IS-merged pages). SYNTHETIC fixtures only.

Shape: a bare JSON array of computer rows, each carrying totalRows, computerId, lastCheckin, mode,
maintenanceTypeId, activeMaintenanceModes, driverStatusString, isDeleted and maintenanceCapabilities (module
flags). Each case runs as plain Python and in the Token-Service sandbox replica.

isEDRDeployed is not evaluated for EVERY input: no documented PortalAPI field exposes ThreatLocker Detect, so
not even a fleet with maintenanceCapabilities.detect true or false may answer.
"""
import copy
import importlib.util
import pathlib
from datetime import datetime, timedelta

import pytest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]

TAG = "tlatlas"
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


def load(name, mode):
    path = HERE / (name + ".py")
    if mode == "sandbox":
        return load_code(path.read_text(), "<transformation>")["transform"]
    spec = importlib.util.spec_from_file_location(TAG + "_" + name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.transform


def run(name, key, body, mode):
    out = load(name, mode)(copy.deepcopy(body))
    return out["transformedResponse"].get(key), out["additionalInfo"]["dataCollection"]["status"], out


def ts(body):
    return {"data": body, "validation": {"status": "skipped", "errors": [], "warnings": []}}


def iso(days_ago):
    return (datetime.utcnow() - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%S.000000Z")


NO_EVIDENCE = [None, {}, [], "", {"error": True, "statusCode": 403, "message": "Forbidden"},
               {"errors": [{"code": 4030010, "title": "Insufficient permissions"}]},
               {"error": True, "statusCode": 412, "message": "Required integration credentials are not connected"}]
KEYS = ["isEDRDeployed", "isEPPDeployed", "requiredCoveragePercentage", "isEPPConfigured"]


def computer(i, total, detect=False, mode="Secure", driver="Active", days=0, deleted=False, maint=0):
    return {"computerId": "c-" + str(i), "computerName": "PC" + str(i), "totalRows": total,
            "lastCheckin": iso(days).replace(".000000", ""), "mode": mode, "maintenanceTypeId": maint,
            "activeMaintenanceModes": [], "driverStatusString": driver, "isDeleted": deleted,
            "maintenanceCapabilities": {"applicationControl": True, "networkControl": True, "storageControl": True,
                                        "elevation": True, "tamper": True, "detect": detect}}


def fleet(n, **kw):
    return [computer(i, n, **kw) for i in range(n)]


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("wrap", [lambda b: b, ts, lambda b: {"result": b}])
def test_good_fleet(mode, wrap):
    rows = fleet(4)
    rows[0]["maintenanceCapabilities"]["detect"] = True
    assert run("isEPPDeployed", "isEPPDeployed", wrap(rows), mode)[:2] == (True, "success")
    assert run("requiredCoveragePercentage", "requiredCoveragePercentage", wrap(rows), mode)[:2] == (100.0, "success")
    assert run("isEPPConfigured", "isEPPConfigured", wrap(rows), mode)[:2] == (100, "success")


@pytest.mark.parametrize("mode", MODES)
def test_bad_posture(mode):
    rows = fleet(4)
    rows[1]["mode"] = "Application Control Learning Mode"
    rows[1]["maintenanceTypeId"] = 3
    rows[2]["driverStatusString"] = "Inactive"
    rows[3]["mode"] = "Secure"
    rows[3]["activeMaintenanceModes"] = [{"maintenanceTypeId": 1}]
    assert run("requiredCoveragePercentage", "requiredCoveragePercentage", rows, mode)[:2] == (75.0, "success")
    assert run("isEPPConfigured", "isEPPConfigured", rows, mode)[:2] == (50, "success")
    dead = fleet(2, driver="Inactive")
    assert run("isEPPDeployed", "isEPPDeployed", dead, mode)[:2] == (False, "success")


@pytest.mark.parametrize("mode", MODES)
def test_stale_and_deleted_not_judged(mode):
    rows = fleet(3)
    rows[1]["lastCheckin"] = iso(40).replace(".000000", "")
    rows[1]["driverStatusString"] = "Inactive"
    rows[2]["isDeleted"] = True
    rows[2]["driverStatusString"] = "Inactive"
    v, dc, out = run("requiredCoveragePercentage", "requiredCoveragePercentage", rows, mode)
    assert (v, dc) == (100.0, "success")
    assert out["transformedResponse"]["staleComputerCount"] == 1


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("body", [fleet(3)[:2],                      # page 1 of a larger organisation
                                  [dict(computer(1, 1), totalRows=None)],
                                  [dict(computer(1, 1), computerId="")],
                                  fleet(2, days=40)] + NO_EVIDENCE)
def test_partial_or_no_evidence_is_unevaluated(mode, body):
    for key in KEYS:
        for b in (body, ts(body)):
            assert run(key, key, b, mode)[:2] == (None, "error"), (key, b)


@pytest.mark.parametrize("mode", MODES)
def test_missing_field_is_unevaluated(mode):
    rows = fleet(2)
    del rows[0]["maintenanceCapabilities"]
    rows = fleet(2)
    del rows[0]["driverStatusString"]
    assert run("isEPPDeployed", "isEPPDeployed", rows, mode)[:2] == (None, "error")
    assert run("requiredCoveragePercentage", "requiredCoveragePercentage", rows, mode)[:2] == (None, "error")
    rows = fleet(2)
    rows[0]["mode"] = None
    assert run("isEPPConfigured", "isEPPConfigured", rows, mode)[:2] == (None, "error")


@pytest.mark.parametrize("mode", MODES)
def test_stringified_scalars(mode):
    rows = fleet(2)
    for r in rows:
        r["totalRows"] = "2"
        r["maintenanceTypeId"] = "0"
        r["isDeleted"] = "False"
        r["maintenanceCapabilities"]["detect"] = "True"
    assert run("isEPPConfigured", "isEPPConfigured", rows, mode)[:2] == (100, "success")


EDR_REASON = "ThreatLocker Detect state is not exposed by a documented API field"


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("detect", [True, False, "True", "False", None])
def test_edr_is_unevaluated_for_every_input(mode, detect):
    rows = fleet(3)
    for r in rows:
        r["maintenanceCapabilities"]["detect"] = detect
        r["isOpsAlertsDisabled"] = False
    bodies = [rows, ts(rows), {"result": rows}, fleet(3)[:2], fleet(2, driver="Inactive")] + NO_EVIDENCE
    for b in bodies:
        v, dc, out = run("isEDRDeployed", "isEDRDeployed", b, mode)
        assert (v, dc) == (None, "error"), b
        assert out["additionalInfo"]["dataCollection"]["errors"] == [EDR_REASON]
        assert out["transformedResponse"] == {"isEDRDeployed": None}
