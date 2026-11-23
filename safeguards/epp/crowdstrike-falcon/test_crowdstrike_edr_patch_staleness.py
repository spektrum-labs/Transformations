"""CrowdStrike Falcon isEDRDeployed and isPatchManagementEnabled (isPatchManagementEnabledFromHosts.py)
apply the same reporting window as requiredCoveragePercentage: a sensor whose last_seen is more than
ACTIVE_WINDOW_DAYS before the newest check-in is not streaming and is not judged. The patch check's
active set is coverage's, so a network-contained host is judged there too. Synthetic hosts."""
import importlib.util
import pathlib
from datetime import datetime, timedelta

HERE = pathlib.Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location("csedrpatch_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


EDR = load("isEDRDeployed")
PATCH = load("isPatchManagementEnabledFromHosts")
NOW = datetime.utcnow().replace(microsecond=0)


def ago(**kw):
    return (NOW - timedelta(**kw)).strftime("%Y-%m-%dT%H:%M:%SZ")


def host(i, seen=None, status="normal", rfm="no", sensor_update=None):
    return {"device_id": f"d{i}", "hostname": f"h{i}", "platform_name": "Windows",
            "product_type_desc": "Workstation", "status": status, "agent_version": "7.40.1",
            "reduced_functionality_mode": rfm, "last_seen": ago(minutes=5) if seen is None else seen,
            "device_policies": {"sensor_update": sensor_update or {"policy_id": "su1", "applied": True}}}


def body(hosts):
    return {"resources": hosts, "meta": {"pagination": {"offset": 0, "limit": 5000, "total": len(hosts)}}}


def edr(hosts):
    out = EDR.transform(body(hosts))
    return out["transformedResponse"], out["additionalInfo"]


# --- isEDRDeployed ---

def test_edr_only_stale_sensors_is_not_deployed():
    result, info = edr([host(0, seen=ago(days=20)), host(1, seen=ago(days=40)), host(2, seen=ago(minutes=1), rfm="yes")])
    assert result["isEDRDeployed"] is False
    assert info["dataCollection"]["status"] == "success"
    assert info["transformation"]["inputSummary"]["notReportingCount"] == 2
    assert "2 not reporting" in info["evaluation"]["failReasons"][0]


def test_edr_one_reporting_sensor_is_deployed_and_stale_ones_are_called_out():
    result, info = edr([host(0), host(1, seen=ago(days=30))])
    assert (result["isEDRDeployed"], result["deployedCount"]) == (True, 1)
    assert "within 15 days of the newest check-in" in info["evaluation"]["passReasons"][0]
    assert any("1 device(s) have not checked in within 15 days" in f for f in info["evaluation"]["additionalFindings"])


def test_edr_unreadable_last_seen_is_not_streaming():
    for bad in (None, "", "soon"):
        h = host(1)
        h["last_seen"] = bad
        assert edr([host(0, rfm="yes"), h])[0]["isEDRDeployed"] is False, bad


def test_edr_dark_fleet_is_not_deployed():
    assert edr([host(i, seen=ago(days=25)) for i in range(3)])[0]["isEDRDeployed"] is False


def test_edr_summary_is_unchanged_when_every_host_reports():
    _, info = edr([host(0)])
    assert "notReportingCount" not in info["transformation"]["inputSummary"]


# --- isPatchManagementEnabled ---

def auto_hash():
    """A settings_hash the check reads as automatic, found from the check's own parser."""
    for candidate in ("tagged|1;101", "tagged|2;101", "tagged|3;101"):
        if PATCH.update_mode({"policy_id": "su1", "applied": True, "settings_hash": candidate}) == "auto":
            return candidate
    raise AssertionError("no automatic settings_hash recognised")


def phost(i, **kw):
    return host(i, sensor_update={"policy_id": "su1", "applied": True, "settings_hash": auto_hash()}, **kw)


def patch(hosts):
    out = PATCH.transform(body(hosts))
    return out["transformedResponse"], out["additionalInfo"]


def test_patch_stale_host_without_automatic_updates_is_not_judged():
    stale = host(1, seen=ago(days=20), sensor_update={"policy_id": "su2", "applied": True, "settings_hash": "21309;5"})
    result, info = patch([phost(0), stale])
    assert result["isPatchManagementEnabled"] is True
    assert info["transformation"]["inputSummary"]["notReportingSkipped"] == 1
    assert "within 15 days of the newest check-in" in info["evaluation"]["passReasons"][0]


def test_patch_contained_host_is_judged():
    contained = host(1, status="contained")
    contained["device_policies"] = {}  # no sensor-update policy
    result, info = patch([phost(0), contained])
    assert result["isPatchManagementEnabled"] is False
    assert info["transformation"]["inputSummary"]["activeSensorsJudged"] == 2


def test_patch_only_stale_hosts_cannot_be_shown():
    result, info = patch([phost(i, seen=ago(days=30)) for i in range(2)])
    assert result["isPatchManagementEnabled"] is False
    assert "2 not seen within 15 days" in info["evaluation"]["failReasons"][0]
