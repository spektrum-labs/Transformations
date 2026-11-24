"""realTimeProtectionCompliancePercentage on the Windows Defender (classic) real-time protection check.

Same key and rounding as the One-Click file (microsoft_endpoint_scid_compliance.py), so one requirement bar reads
both integrations. Unreadable states stay in the denominator and never count as protected. Every body that
proves nothing reads None with a dataCollection error. Synthetic rows; each case also runs in the sandbox replica.
"""
import importlib.util
import pathlib

import pytest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
KEY = "realTimeProtectionCompliancePercentage"
BOOL = "isRealTimeProtectionEnabled"

TAG = "rtppct"
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


def run(body, mode, name="isrealtimeprotectionenabled"):
    out = load(name, mode)(body)
    return out["transformedResponse"], out["additionalInfo"]["dataCollection"]


def hunting(rows):
    return {"Schema": [{"Name": "ConfigurationId", "Type": "String"}], "Results": rows}


def row(i, compliant, applicable=1, scid="scid-2012"):
    return {"DeviceId": "dev-" + str(i), "DeviceName": "host-" + str(i), "ConfigurationId": scid,
            "IsCompliant": compliant, "IsApplicable": applicable}


def fleet(n, off=0, unreadable=0):
    rows = [row(i, "1") for i in range(n - off - unreadable)]
    rows += [row(1000 + i, "0") for i in range(off)]
    rows += [row(2000 + i, None) for i in range(unreadable)]
    return rows


@pytest.mark.parametrize("mode", MODES)
def test_near_complete_fleet_reads_99(mode):
    result, dc = run(hunting(fleet(200, off=2)), mode)
    assert dc["status"] == "success"
    assert result[KEY] == 99
    assert result["realTimeProtectedCount"] == 198


@pytest.mark.parametrize("mode", MODES)
def test_matches_one_click_on_the_same_rows(mode):
    rows = hunting(fleet(150, off=3))
    classic, _ = run(rows, mode)
    one_click, _ = run(rows, mode, "microsoft_endpoint_scid_compliance")
    assert classic[KEY] == one_click[KEY] == 98


@pytest.mark.parametrize("mode", MODES)
def test_full_and_zero(mode):
    assert run(hunting(fleet(4)), mode)[0][KEY] == 100
    result, dc = run(hunting(fleet(4, off=4)), mode)
    assert (result[KEY], result[BOOL], dc["status"]) == (0, False, "success")


@pytest.mark.parametrize("mode", MODES)
def test_unreadable_state_is_never_protected(mode):
    result, dc = run(hunting(fleet(10, unreadable=1)), mode)
    assert dc["status"] == "success"
    assert result[KEY] == 90
    assert result["unreadableDevices"] == 1


@pytest.mark.parametrize("mode", MODES)
def test_not_applicable_rows_are_left_out(mode):
    rows = fleet(4) + [row(9, "0", applicable="0")]
    assert run(hunting(rows), mode)[0][KEY] == 100


@pytest.mark.parametrize("mode", MODES)
def test_machines_api_av_mode(mode):
    rows = [{"computerDnsName": "m" + str(i), "avMode": "Active"} for i in range(3)]
    rows.append({"computerDnsName": "m9", "avMode": "Passive"})
    result, dc = run({"value": rows}, mode)
    assert (result[KEY], dc["status"]) == (75, "success")


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("body", [
    None, {}, [], "", "{}", {"Results": []}, {"value": []}, {"error": {"code": "Forbidden"}},
    hunting([row(1, None), row(2, "None")]),                      # nothing readable
    hunting([row(1, "1", applicable="0")]),                         # nothing applicable
    hunting([row(1, "1", scid="scid-2011")]),                       # wrong configuration id
    {"value": [{"computerDnsName": "m1", "avMode": None}]},
])
def test_no_evidence_is_unevaluated(mode, body):
    result, dc = run(body, mode)
    assert result[KEY] is None and result[BOOL] is None, body
    assert dc["status"] == "error" and dc["errors"], body
