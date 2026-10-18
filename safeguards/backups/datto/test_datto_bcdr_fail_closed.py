"""Datto BCDR (integration e0d463e8) checks on the getDevices -> getDeviceStatus workflow.

The workflow calls GET /v1/bcdr/device, then GET /v1/bcdr/device/{serialNumber}/asset per device, and hands
the transform {"devices": [<asset list per device>, ...]}. Asset field names follow the Datto REST API
DeviceAsset / Snapshot model (lastSnapshot, isPaused, isArchived, lastScreenshotAttemptStatus,
backups[].localVerification / advancedVerification.screenshotVerification); values are synthetic. Datto
Backup for Microsoft Azure devices (model CLDSIRIS) are served by the same endpoints.

Fail closed: a body that proves nothing (None, {}, [], "", 401/403/error envelopes, an empty device or asset
list, unrelated JSON, archived-only assets, a per-device error) returns the key as None with dataCollection
"error", never a definite answer. Each check also has a passing body and a flip that must change the answer.
"""
import copy
import importlib.util
import pathlib

import pytest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]

try:
    import RestrictedPython  # noqa: F401
    spec = importlib.util.spec_from_file_location("restricted_sandbox_datto_bcdr", ROOT / "tools" / "restricted_sandbox.py")
    sandbox = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sandbox)
    load_code = sandbox.load
except ImportError:
    def load_code(code, filename):
        ns = {"__name__": "datto_bcdr_" + filename}
        exec(compile(code, filename, "exec"), ns)
        return ns

KEYS = ["isBackupEnabled", "isBackupLoggingEnabled", "confirmedLicensePurchased", "isBackupTested",
        "isBackupEncrypted", "isBackupTypesScheduled"]


def run(key, body):
    out = load_code((HERE / (key.lower() + ".py")).read_text(), key)["transform"](body)
    return out["transformedResponse"][key], out["additionalInfo"]["dataCollection"]["status"]


def asset(name, paused=False, snap=1759180000, shot=True, backups=True, archived=False):
    b = [{"timestamp": "2026-09-29T10:00:00Z", "backup": {"status": "success", "errorMessage": None},
          "localVerification": {"status": "success" if shot else "failure", "errors": []},
          "advancedVerification": {"screenshotVerification": {"status": "success" if shot else "failure", "image": ""}}}]
    return {"name": name, "assetId": 1, "agentVersion": "3.1", "isPaused": paused, "isArchived": archived,
            "lastSnapshot": snap, "localSnapshots": 12, "lastScreenshotAttempt": snap,
            "lastScreenshotAttemptStatus": shot, "backups": b if backups else [], "protectedVolumesCount": 2}


REAL = {"devices": [[asset("vm1"), asset("vm2")], [asset("vm3", shot=False)]]}
FLIPPED = {"devices": [[{"name": "vm1", "agentVersion": "3.1", "isPaused": True, "isArchived": False, "lastSnapshot": 0,
                        "lastScreenshotAttemptStatus": False, "backups": [], "encryption": False}]]}
NO_EVIDENCE = {
    "none": None, "empty_dict": {}, "empty_list": [], "empty_string": "",
    "auth_401": {"statusCode": 401, "message": "Unauthorized"},
    "auth_401_nested": {"response": {"statusCode": 401, "message": "Unauthorized"}},
    "auth_403_snake": {"status_code": 403, "detail": "Forbidden"}, "error": {"error": "invalid key"},
    "no_devices": {"devices": []}, "empty_asset_list": {"devices": [[]]},
    "empty_device_list": {"items": [], "pagination": {"count": 0}},
    "unrelated": {"foo": "bar"}, "unrelated_nested": {"data": {"rows": [{"x": 1}]}},
    "device_list_only": {"items": [{"serialNumber": "S1", "model": "CLDSIRIS"}]},
    "archived_only": {"devices": [[asset("vm1", archived=True)]]},
    "device_error": {"devices": [[asset("vm1")], {"error": "timeout"}]},
}


@pytest.mark.parametrize("key", KEYS)
def test_real_body_passes(key):
    assert run(key, copy.deepcopy(REAL)) == (True, "success")
    assert run(key, {"apiResponse": copy.deepcopy(REAL)}) == (True, "success")


@pytest.mark.parametrize("key", [k for k in KEYS if k != "confirmedLicensePurchased"])
def test_flip_fails(key):
    assert run(key, copy.deepcopy(FLIPPED)) == (False, "success")


@pytest.mark.parametrize("key", KEYS)
@pytest.mark.parametrize("probe", sorted(NO_EVIDENCE))
def test_no_evidence_is_not_measured(key, probe):
    assert run(key, copy.deepcopy(NO_EVIDENCE[probe])) == (None, "error")


def test_percentages_are_emitted():
    out = load_code((HERE / "isbackuptested.py").read_text(), "t")["transform"](copy.deepcopy(REAL))
    assert out["transformedResponse"]["backupTestedPercentage"] == 66.7
