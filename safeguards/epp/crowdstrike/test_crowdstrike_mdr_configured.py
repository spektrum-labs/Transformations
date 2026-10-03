"""CrowdStrike isMDRConfigured (epp_transform.py).

isMDRConfigured used to be a copy of isMDREnabled (MDR coverage > 0, where rtr_state "enabled"
alone counts a host). It is now the share of hosts with a live sensor (status normal, not reduced
functionality mode, agent_version and last_seen present) AND the prevention AND remote_response
policies applied, against a 95% threshold; None when there is no device list or the list is
shorter than meta.pagination.total.

Synthetic bodies in the real GET /devices/combined/devices/v1 shape (policy flags as the strings
"True"/"False", as stored). Populated, flipped, empty, None, 401, 403, truncated."""
import importlib.util
import pathlib

HERE = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("cs_epp_transform", HERE / "epp_transform.py")
EPP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EPP)
AUTH_401 = {"errors": [{"code": 401, "message": "access denied, authorization failed"}], "resources": [], "meta": {}}
AUTH_403 = {"errors": [{"code": 403, "message": "access denied, authorization failed"}], "resources": [], "meta": {}}


def device(prevention="True", response="True", status="normal", rfm="no"):
    return {"device_id": "d", "status": status, "reduced_functionality_mode": rfm, "agent_version": "7.20",
            "last_seen": "2026-09-29T05:00:00Z", "rtr_state": "enabled", "product_type_desc": "Workstation",
            "device_policies": {"prevention": {"applied": prevention, "policy_id": "p"},
                                "remote_response": {"applied": response, "policy_id": "r"}}}


def body(devices, total=None):
    total = len(devices) if total is None else total
    return {"meta": {"pagination": {"total": str(total), "limit": "5000"}}, "resources": devices, "errors": []}


def mdr(payload):
    out = EPP.transform(payload)["transformedResponse"]
    return out.get("isMDRConfigured"), out.get("mdrConfiguredPercentage"), out.get("isMDREnabled")


def test_ready_estate_is_configured():
    # 957 ready hosts, 4 with no status and reduced functionality mode
    devices = [device() for _ in range(957)] + [device(status=None, rfm="yes") for _ in range(4)]
    assert mdr(body(devices)) == (True, 99.58, True)


def test_hosts_without_remote_response_policy_are_not_configured_although_mdr_is_enabled():
    devices = [device() for _ in range(80)] + [device(response="False") for _ in range(20)]
    assert mdr(body(devices)) == (False, 80.0, True)


def test_prevention_policy_not_applied_counts_against_configuration():
    devices = [device() for _ in range(90)] + [device(prevention=False) for _ in range(10)]
    assert mdr(body(devices))[:2] == (False, 90.0)


def test_boolean_flags_and_threshold():
    assert mdr(body([device(True, True) for _ in range(95)] + [device(True, False) for _ in range(5)]))[:2] == (True, 95.0)


def test_truncated_device_list_is_unanswered():
    assert mdr(body([device() for _ in range(100)], total=1511))[:2] == (None, None)


def test_no_evidence_is_unanswered_not_copied_from_enabled():
    for payload in ({}, None, [], AUTH_401, AUTH_403, body([])):
        assert mdr(payload)[:2] == (None, None), payload
