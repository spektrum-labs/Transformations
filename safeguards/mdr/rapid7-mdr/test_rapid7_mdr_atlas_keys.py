"""Rapid7 MDR (58ba5ce2): isEDRDeployed from getHealthMetrics and isAlertingEnabled from listInvestigations.
SYNTHETIC fixtures only, InsightIDR shapes as in test_rapid7_mdr_bundle_keys.py. Each case runs as plain Python
and in the Token-Service sandbox replica.
"""
import copy
import importlib.util
import pathlib
from datetime import datetime, timedelta

import pytest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]

TAG = "r7atlas"
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
ORG = "00000000-0000-0000-0000-000000000001"


def health(online, offline, stale, total, extra=1):
    rows = [{"rrn": "rrn:agents:us:" + ORG + ":status:summary", "online": online, "offline": offline,
             "stale": stale, "total": total}]
    rows += [{"rrn": "rrn:collection:us:" + ORG + ":collector:c" + str(i), "state": "RUNNING"} for i in range(extra)]
    return {"data": rows, "metadata": {"index": 0, "size": 100, "total_pages": 1, "total_data": len(rows)}}


def inv(i, days, source="ALERT"):
    t = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    return {"rrn": "rrn:investigation:us:" + ORG + ":investigation:I" + str(i), "source": source,
            "created_time": t, "status": "CLOSED", "title": "Synthetic"}


def invs(rows, total=None):
    return {"data": rows, "metadata": {"index": 0, "size": 100, "total_pages": 1,
                                       "total_data": len(rows) if total is None else total}}


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("wrap", [lambda b: b, ts])
def test_edr(mode, wrap):
    assert run("isEDRDeployed", "isEDRDeployed", wrap(health(10, 5, 1, 16)), mode)[:2] == (True, "success")
    assert run("isEDRDeployed", "isEDRDeployed", wrap(health(0, 0, 7, 7)), mode)[:2] == (False, "success")
    assert run("isEDRDeployed", "isEDRDeployed", wrap(health(0, 0, 0, 0)), mode)[:2] == (False, "success")


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("body", [health(10, 5, 1, 12), health("x", 1, 1, 3),
                                  {"data": [{"rrn": "rrn:collection:us:o:collector:c", "state": "RUNNING"}],
                                   "metadata": {"total_data": 1}},
                                  invs([inv(1, 1)])] + NO_EVIDENCE)
def test_edr_unevaluated(mode, body):
    for b in (body, ts(body)):
        assert run("isEDRDeployed", "isEDRDeployed", b, mode)[:2] == (None, "error")


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("wrap", [lambda b: b, ts])
def test_alerting(mode, wrap):
    assert run("isAlertingEnabled", "isAlertingEnabled", wrap(invs([inv(1, 3), inv(2, 200)])), mode)[:2] == (True, "success")
    assert run("isAlertingEnabled", "isAlertingEnabled", wrap(invs([inv(1, 200), inv(2, 5, "MANUAL")])), mode)[:2] == (False, "success")


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("body", [invs([inv(1, 200)], total=5), invs([]), health(1, 1, 1, 3)] + NO_EVIDENCE)
def test_alerting_unevaluated(mode, body):
    for b in (body, ts(body)):
        assert run("isAlertingEnabled", "isAlertingEnabled", b, mode)[:2] == (None, "error")
