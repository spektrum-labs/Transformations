"""isPatchManagementEnabled: /v2/policies carries no OS patching setting, so a recent INSTALLED patch on an
in-scope OS device (osPatchInstalls) proves patching runs. Everything else keeps the policy-only verdict
(synthetic data)."""
import importlib.util
import pathlib
import time

HERE = pathlib.Path(__file__).resolve().parent
KEY = "isPatchManagementEnabled"


def run(body):
    spec = importlib.util.spec_from_file_location("n1_patch_installs", HERE / (KEY + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform(body)


DAY = 86400
NOW = time.time()
DEVICES = [{"id": 1, "nodeClass": "MAC", "policyId": 501, "rolePolicyId": 502},
           {"id": 2, "nodeClass": "WINDOWS_WORKSTATION", "policyId": [], "rolePolicyId": 503},
           {"id": 3, "nodeClass": "APPLE_IOS", "policyId": [], "rolePolicyId": 504}]
# What the projected /v2/policies summary really looks like: no patch setting, missing fields default to [].
POLICIES = [{"id": i, "name": "P%d" % i, "nodeClass": nc, "enabled": [], "parentPolicyId": [], "conditions": []}
            for i, nc in ((501, "MAC"), (502, "MAC"), (503, "WINDOWS_WORKSTATION"), (504, "APPLE_IOS"))]


def body(installs):
    out = {"devices": DEVICES, "policies": POLICIES}
    if installs is not None:
        out["osPatchInstalls"] = installs
    return out


def install(device, days_ago, status="INSTALLED"):
    return {"id": "x", "deviceId": device, "status": status, "installedAt": NOW - days_ago * DAY}


def verdict(installs):
    return run(body(installs))["transformedResponse"]


def test_recent_install_on_in_scope_os_device_passes():
    out = verdict({"cursor": [], "results": [install(2, 3)]})
    assert out[KEY] is True
    assert out["recentPatchInstalls"] == 1


def test_bare_list_part_is_read_too():
    assert verdict([install(1, 1)])[KEY] is True


def test_no_installs_part_keeps_policy_only_fail():
    assert verdict(None)[KEY] is False


def test_stale_failed_or_non_os_installs_do_not_count():
    rows = [install(2, 45), install(2, 1, "FAILED"), install(3, 1), install(99, 1)]
    out = verdict({"cursor": [], "results": rows})
    assert out[KEY] is False
    assert out["recentPatchInstalls"] == 0


def test_empty_or_unreadable_installs_never_pass():
    assert verdict({"cursor": [], "results": []})[KEY] is False
    resp = run(body({"error": "boom"}))
    assert resp["transformedResponse"][KEY] is False
    assert any("could not be read" in r for r in resp["additionalInfo"]["evaluation"]["failReasons"])
    for junk in ("text", 5, [None, "x", {"status": "INSTALLED", "installedAt": True, "deviceId": 2}]):
        assert verdict(junk)[KEY] is False


def test_without_device_list_any_recent_install_counts():
    out = run({"policies": POLICIES, "osPatchInstalls": {"results": [install(77, 2)]}})["transformedResponse"]
    assert out[KEY] is True
