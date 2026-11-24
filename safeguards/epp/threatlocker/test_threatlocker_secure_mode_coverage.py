"""ThreatLocker secureModeCoveragePercentage from getComputers (the response isEPPEnabled reads).
SYNTHETIC fixtures only. Each case runs as plain Python and in the Token-Service sandbox replica.

A near-complete fleet reads as a high percentage (the bar lives in the requirement) where isEPPEnabled fails it
outright; every body that proves nothing reads None with a dataCollection error.
"""
import copy
import importlib.util
import pathlib
from datetime import datetime, timedelta

import pytest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]
KEY = "secureModeCoveragePercentage"

TAG = "tlsecure"
try:
    import RestrictedPython  # noqa: F401
    spec = importlib.util.spec_from_file_location("restricted_sandbox_" + TAG, ROOT / "tools" / "restricted_sandbox.py")
    sandbox = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sandbox)
    load_code = sandbox.load
except ImportError:
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


def run(body, mode, name="secureModeCoveragePercentage", key=KEY):
    out = load(name, mode)(copy.deepcopy(body))
    return out["transformedResponse"].get(key), out["additionalInfo"]["dataCollection"]["status"], out


def ts(body):
    return {"data": body, "validation": {"status": "skipped", "errors": [], "warnings": []}}


def iso(days_ago):
    return (datetime.utcnow() - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%S")


def computer(i, total, mode="Secure", days=0, deleted=False, maint=0):
    return {"computerId": "c-" + str(i), "computerName": "PC" + str(i), "totalRows": total,
            "lastCheckin": iso(days), "mode": mode, "maintenanceTypeId": maint, "activeMaintenanceModes": [],
            "driverStatusString": "Active", "isDeleted": deleted}


def fleet(n, **kw):
    return [computer(i, n, **kw) for i in range(n)]


NO_EVIDENCE = [None, {}, [], "", "{}", {"error": True, "statusCode": 403, "message": "Forbidden"},
               {"errors": [{"code": 4030010, "title": "Insufficient permissions"}]}, {"statusCode": 500}]


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("wrap", [lambda b: b, ts, lambda b: {"apiResponse": b}])
def test_full_fleet_is_100(mode, wrap):
    assert run(wrap(fleet(5)), mode)[:2] == (100, "success")


@pytest.mark.parametrize("mode", MODES)
def test_near_complete_fleet_reads_as_a_share_not_a_fail(mode):
    rows = fleet(200)
    rows[7]["mode"] = "Learning"
    value, status, out = run(rows, mode)
    assert (value, status) == (99, "success")
    assert out["transformedResponse"]["secureModeComputers"] == 199
    assert out["transformedResponse"]["judgedComputers"] == 200
    # isEPPEnabled, on the same body, fails the whole fleet over one machine
    assert run(rows, mode, "isEPPEnabled", "isEPPEnabled")[0] is False


@pytest.mark.parametrize("mode", MODES)
def test_share_is_rounded_down(mode):
    rows = fleet(3)
    rows[0]["mode"] = "Monitor Only"
    assert run(rows, mode)[:2] == (66, "success")
    rows = fleet(50)
    rows[0]["mode"] = "Installation"
    assert run(rows, mode)[:2] == (98, "success")


@pytest.mark.parametrize("mode", MODES)
def test_maintenance_mode_is_not_secure(mode):
    rows = fleet(4)
    rows[1]["activeMaintenanceModes"] = [{"maintenanceTypeId": 1}]
    rows[2]["maintenanceTypeId"] = "3"
    assert run(rows, mode)[:2] == (50, "success")


@pytest.mark.parametrize("mode", MODES)
def test_stale_and_deleted_not_judged(mode):
    rows = fleet(4)
    rows[1]["lastCheckin"] = iso(40)
    rows[1]["mode"] = "Learning"
    rows[2]["isDeleted"] = True
    rows[2]["mode"] = "Learning"
    value, status, out = run(rows, mode)
    assert (value, status) == (100, "success")
    assert out["transformedResponse"]["staleComputerCount"] == 1


@pytest.mark.parametrize("mode", MODES)
def test_zero_secure_is_zero_not_none(mode):
    assert run(fleet(3, mode="Learning"), mode)[:2] == (0, "success")


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("body", [fleet(3)[:2],                      # page 1 of a larger organisation
                                  [dict(computer(1, 1), totalRows=None)],
                                  [dict(computer(1, 1), computerId="")],
                                  [dict(computer(1, 1), mode=None)],
                                  [dict(computer(1, 1), mode="")],
                                  fleet(2, days=40),
                                  fleet(2, deleted=True)] + NO_EVIDENCE)
def test_no_evidence_is_unevaluated(mode, body):
    for b in (body, ts(body)):
        value, status, out = run(b, mode)
        assert (value, status) == (None, "error"), b
        assert out["additionalInfo"]["dataCollection"]["errors"]
