"""CrowdStrike isPatchManagementEnabled read from host records (Hosts: Read), not from
/policy/combined/sensor-update (Sensor update policies: Read).

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


def test_one_host_with_updates_off_or_pinned_or_no_policy_fails():
    for flip in (";101", "3623;101"):
        body = copy.deepcopy(HOSTS)
        first_active(body)["device_policies"]["sensor_update"]["settings_hash"] = flip
        assert verdict(body) == (False, "success"), flip
    body = copy.deepcopy(HOSTS)
    first_active(body)["device_policies"] = {}
    assert verdict(body) == (False, "success")


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
    body = copy.deepcopy(HOSTS)
    host = first_active(body)
    host["status"] = "containment_pending"
    host["device_policies"] = {}
    assert verdict(body) == (False, "success")


def test_truncated_list_and_non_host_bodies_are_not_measured():
    body = copy.deepcopy(HOSTS)
    body["meta"]["pagination"]["total"] = 1511
    assert verdict(body) == (False, "error")
    assert verdict(POLICIES) == (False, "error")  # sensor/prevention policy body wired by mistake


def test_empty_none_error():
    assert verdict({"resources": [], "meta": {"pagination": {"total": 0}}}) == (False, "success")
    for body in ({}, None, "{}", ERROR):
        assert verdict(body) == (False, "error"), body
