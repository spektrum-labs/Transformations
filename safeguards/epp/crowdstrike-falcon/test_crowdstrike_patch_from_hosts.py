"""CrowdStrike isPatchManagementEnabled read from host records (Hosts: Read), not from
/policy/combined/sensor-update (Sensor update policies: Read). Passes when at least 99% of active
sensors have automatic sensor updates on; sensors below that are listed in the findings.

Real payload (2026-09-25, redacted to the fields read, ids replaced): a Falcon EPP tenant's
getDeviceDetails, 130 hosts, every sensor-update settings_hash a tagged release.
Real, flipped, empty, None, error, truncated, and the old policy-shaped body."""
import copy
import importlib.util
import json
import pathlib
from datetime import datetime, timedelta

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("cs_patch_hosts", HERE / "isPatchManagementEnabledFromHosts.py")
MOD = importlib.util.module_from_spec(spec)
spec.loader.exec_module(MOD)
HOSTS = json.loads((HERE / "fixtures" / "falcon_hosts_sensor_update_real_2026-09-25.json").read_text())


def shift_to_present(body):
    """Move every last_seen by the same amount so the newest is now: the real spread is kept, and the
    15-day reporting window never ages the fixture into a dark fleet."""
    seen = [datetime.fromisoformat(h["last_seen"][:19]) for h in body["resources"]]
    shift = datetime.utcnow() - max(seen)
    for h, when in zip(body["resources"], seen):
        h["last_seen"] = (when + shift).strftime("%Y-%m-%dT%H:%M:%SZ")
    return body


shift_to_present(HOSTS)
POLICIES = json.loads((HERE / "fixtures" / "falcon_complete_prevention_policies_real_2026-09-25.json").read_text())
ERROR = {"error": True, "message": "Integration execution error: HTTP 403: Forbidden"}


def verdict(body):
    out = MOD.transform(body)
    return out["transformedResponse"]["isPatchManagementEnabled"], out["additionalInfo"]["dataCollection"]["status"]


def first_active(body):
    for h in body["resources"]:
        if h["status"] == "normal" and h["reduced_functionality_mode"] != "yes":
            return h
    raise AssertionError("no active host")


def test_real_hosts_all_tagged_pass():
    assert verdict(HOSTS) == (True, "success")
    assert verdict(json.dumps(HOSTS)) == (True, "success")
    assert verdict({"apiResponse": HOSTS}) == (True, "success")


def fleet(total, off, mode=";101"):
    """`total` active hosts from the real fixture's first active host, `off` of them with the given
    sensor-update settings_hash (default: sensor version updates off). Ids are generated."""
    template = copy.deepcopy(first_active(HOSTS))
    hosts = []
    for i in range(total):
        host = copy.deepcopy(template)
        host["device_id"] = f"fleet-{i:05d}"
        host["hostname"] = f"HOST-{i:05d}"
        if i < off:
            host["device_policies"]["sensor_update"]["settings_hash"] = mode
        hosts.append(host)
    return {"resources": hosts, "meta": {"pagination": {"total": total}}}


def detail(body):
    out = MOD.transform(body)
    return (out["transformedResponse"]["isPatchManagementEnabled"], out["additionalInfo"]["dataCollection"]["status"],
            out["additionalInfo"]["evaluation"])


def test_share_boundary_98_9_fails_99_and_100_pass():
    # 1000 active sensors: 11 off = 98.9% -> fail; 10 off = 99.0% -> pass; 0 off = 100% -> pass
    assert detail(fleet(1000, 11))[:2] == (False, "success")
    assert detail(fleet(1000, 10))[:2] == (True, "success")
    assert detail(fleet(1000, 0))[:2] == (True, "success")


def test_one_sensor_off_in_a_large_fleet_passes_and_is_still_listed():
    value, status, evaluation = detail(fleet(5000, 1))
    assert (value, status) == (True, "success")
    assert evaluation["failReasons"] == []
    assert any("HOST-00000" in f and "updates off" in f for f in evaluation["additionalFindings"])
    assert any("do not update automatically" in r for r in evaluation["recommendations"])


def test_small_fleet_one_off_fails_because_the_share_is_below_99():
    value, status, evaluation = detail(fleet(50, 1))
    assert (value, status) == (False, "success")
    assert any("HOST-00000" in f for f in evaluation["additionalFindings"])


def test_pinned_and_no_policy_count_against_the_share_and_are_listed():
    value, _, evaluation = detail(fleet(100, 2, mode="3623;101"))
    assert value is False
    assert any("pinned" in f for f in evaluation["additionalFindings"])
    body = fleet(100, 0)
    for host in body["resources"][:2]:
        host["device_policies"] = {}
    value, _, evaluation = detail(body)
    assert value is False
    assert any("no sensor-update policy" in f for f in evaluation["additionalFindings"])


def test_findings_name_at_most_25_sensors_and_count_the_rest():
    _, _, evaluation = detail(fleet(1000, 30))
    finding = next(f for f in evaluation["additionalFindings"] if "updates off" in f)
    assert finding.startswith("30 active sensors")
    assert "HOST-00024" in finding and "HOST-00025" not in finding and "and 5 more" in finding


def test_real_hosts_one_off_among_130_passes_but_is_listed():
    body = copy.deepcopy(HOSTS)
    first_active(body)["device_policies"]["sensor_update"]["settings_hash"] = ";101"
    value, status, evaluation = detail(body)
    active = sum(1 for h in body["resources"] if h["status"] == "normal" and h["reduced_functionality_mode"] != "yes")
    if active >= 100:
        assert (value, status) == (True, "success")
    assert evaluation["additionalFindings"]


def test_real_hosts_many_off_or_pinned_or_no_policy_fail():
    for flip in (";101", "3623;101"):
        body = copy.deepcopy(HOSTS)
        for host in [h for h in body["resources"] if h["status"] == "normal" and h["reduced_functionality_mode"] != "yes"][:10]:
            host["device_policies"]["sensor_update"]["settings_hash"] = flip
        assert verdict(body) == (False, "success"), flip
    body = copy.deepcopy(HOSTS)
    for host in [h for h in body["resources"] if h["status"] == "normal" and h["reduced_functionality_mode"] != "yes"][:10]:
        host["device_policies"] = {}
    assert verdict(body) == (False, "success")


def test_zero_active_sensors_is_not_evaluated_never_a_pass():
    assert verdict({"resources": [], "meta": {"pagination": {"total": 0}}}) == (False, "error")
    body = fleet(5, 0)
    for host in body["resources"]:
        host["last_seen"] = (datetime.utcnow() - timedelta(days=40)).strftime("%Y-%m-%dT%H:%M:%SZ")  # dark fleet
    assert verdict(body) == (False, "error")
    mobile_only = {"resources": [{"device_id": "m1", "platform_name": "iOS", "product_type_desc": "Mobile"}],
                   "meta": {"pagination": {"total": 1}}}
    assert verdict(mobile_only) == (False, "error")


def test_unrecognised_settings_hash_is_not_measured():
    body = copy.deepcopy(HOSTS)
    first_active(body)["device_policies"]["sensor_update"]["settings_hash"] = "latest|n"
    assert verdict(body) == (False, "error")


def test_inactive_and_mobile_hosts_are_not_judged():
    body = copy.deepcopy(HOSTS)
    host = first_active(body)
    host["last_seen"] = (datetime.utcnow() - timedelta(days=20)).strftime("%Y-%m-%dT%H:%M:%SZ")  # not reporting
    host["device_policies"] = {}
    body["resources"].append({"device_id": "m1", "platform_name": "Android", "product_type_desc": "Mobile",
                              "status": "normal", "agent_version": "1", "last_seen": first_active(body)["last_seen"],
                              "device_policies": {"mobile": {}}})
    body["meta"]["pagination"]["total"] = len(body["resources"])
    assert verdict(body) == (True, "success")


def test_contained_host_is_active_and_judged_like_coverage_counts_it():
    body = fleet(50, 0)
    host = body["resources"][0]
    host["status"] = "containment_pending"
    host["device_policies"] = {}
    assert verdict(body) == (False, "success")


def test_truncated_list_and_non_host_bodies_are_not_measured():
    body = copy.deepcopy(HOSTS)
    body["meta"]["pagination"]["total"] = 1511
    assert verdict(body) == (False, "error")
    assert verdict(POLICIES) == (False, "error")  # sensor/prevention policy body wired by mistake


def test_empty_none_error():
    for body in ({}, None, "{}", ERROR):
        assert verdict(body) == (False, "error"), body
