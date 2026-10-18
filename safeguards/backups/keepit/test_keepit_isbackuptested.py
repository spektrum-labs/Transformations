"""Keepit (4c7c64a7): isBackupTested from getDeviceJobs (listDevices + per-connector /jobs, xmltodict-parsed).
SYNTHETIC fixtures only. True only for a restore/srestore job that succeeded in the jobs window; no restore, or
only failed ones, is not evaluated (the window is +/-7 days). Each case runs as plain Python and in the
Token-Service sandbox replica.
"""
import copy
import importlib.util
import pathlib
from datetime import datetime, timedelta

import pytest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]

TAG = "keepitatlas"
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
def job(kind, outcome="succeeded", days=1):
    t = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    j = {"guid": "j-" + kind + str(days), "type": kind, "active": "false", "started": t,
         "description": "[" + kind + "] {Synthetic connector}"}
    if outcome:
        j[outcome] = t
    return j


def body(per_connector):
    clouds = [{"guid": "g" + str(i), "name": "Connector " + str(i), "type": "o365"} for i in range(len(per_connector))]
    jobs = [{"jobs": {"job": js if len(js) != 1 else js[0]}} if js else {"jobs": None} for js in per_connector]
    return {"devices": {"cloud": clouds if len(clouds) != 1 else clouds[0]}, "deviceJobs": jobs}


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("wrap", [lambda b: b, ts])
def test_restore_succeeded(mode, wrap):
    b = body([[job("backup"), job("backup", days=2)], [job("srestore"), job("backup")]])
    v, dc, out = run("isbackuptested", "isBackupTested", wrap(b), mode)
    assert (v, dc) == (True, "success")
    assert out["transformedResponse"]["succeededRestores"] == 1
    assert run("isbackuptested", "isBackupTested", wrap(body([[job("restore")]])), mode)[:2] == (True, "success")


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("b", [body([[job("backup")], [job("srestore", "failed")]]),
                               body([[job("backup"), job("zipdownload")]]),
                               body([[]]),
                               body([]),
                               {"devices": {"cloud": [{"guid": "g1", "name": "c"}]}},
                               {"devices": {"cloud": [{"guid": "g1"}, {"guid": "g2"}]}, "deviceJobs": [{"jobs": None}]},
                               ] + NO_EVIDENCE)
def test_no_completed_restore_is_unevaluated(mode, b):
    for x in (b, ts(b)):
        assert run("isbackuptested", "isBackupTested", x, mode)[:2] == (None, "error")
