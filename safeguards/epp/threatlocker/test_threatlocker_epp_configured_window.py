"""ThreatLocker (69b438a1): isEPPConfigured activity window. SYNTHETIC fixtures only.

A computer without a readable lastCheckin is judged beside current dated computers, but when every dated computer
is outside the 15-day window, undated rows alone must not decide the estate: the result is not evaluated (None,
dataCollection "error"). Each case runs as plain Python and in the Token-Service sandbox replica, typed and
stringified (Token-Service stores every leaf as a string).
"""
import copy
import importlib.util
import json
import pathlib
from datetime import datetime, timedelta

import pytest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]
NAME = KEY = "isEPPConfigured"

TAG = "tleppcfgwindow"
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


def computer(i, total, mode="Secure", days=0):
    return {"computerId": "c-" + str(i), "computerName": "PC" + str(i), "totalRows": total,
            "lastCheckin": iso(days), "mode": mode, "maintenanceTypeId": 0, "activeMaintenanceModes": [],
            "driverStatusString": "Active", "isDeleted": False}


def fleet(n, **kw):
    return [computer(i, n, **kw) for i in range(n)]


def stringify(rows):
    def s(v):
        if isinstance(v, dict):
            return {k: s(x) for k, x in v.items()}
        if isinstance(v, list):
            return [s(x) for x in v]
        return str(v)
    return s(rows)


SHAPES = [lambda b: b, ts, lambda b: json.dumps(b), stringify, lambda b: ts(stringify(b))]


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("undated", [None, "", "not a date"])
def test_undated_computer_alone_is_not_judged_when_every_dated_computer_is_stale(mode, shape, undated):
    # 200 stale Learning-mode computers plus 1 undated Secure-mode computer used to return 100.
    rows = fleet(201, mode="Application Control Learning Mode", days=40)
    rows[200].update(mode="Secure", lastCheckin=undated)
    v, dc, out = run(shape(rows), mode)
    assert (v, dc) == (None, "error")
    assert out["transformedResponse"]["staleComputerCount"] == 200
    assert "15 days" in out["additionalInfo"]["dataCollection"]["errors"][0]


@pytest.mark.parametrize("mode", MODES)
def test_every_computer_stale_is_unevaluated(mode):
    assert run(fleet(3, days=40), mode)[:2] == (None, "error")


@pytest.mark.parametrize("mode", MODES)
def test_undated_computer_is_still_judged_beside_a_current_dated_computer(mode):
    rows = fleet(3)
    rows[0].update(lastCheckin=iso(40))
    rows[2].update(mode="Application Control Learning Mode", lastCheckin=None)
    v, dc, out = run(rows, mode)
    assert (v, dc) == (50, "success")
    assert out["transformedResponse"]["judgedComputers"] == 2
    assert out["transformedResponse"]["staleComputerCount"] == 1


@pytest.mark.parametrize("mode", MODES)
def test_no_dated_computer_at_all_is_unchanged(mode):
    # unchanged behaviour: with no readable lastCheckin anywhere, every live computer is judged
    rows = fleet(2)
    for r in rows:
        r["lastCheckin"] = None
    assert run(rows, mode)[:2] == (100, "success")
