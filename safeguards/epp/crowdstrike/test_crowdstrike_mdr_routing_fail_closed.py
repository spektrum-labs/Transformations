"""CrowdStrike - MDR: bodies that are not the evidence a key needs read Unevaluated, not False.

Found 2 Oct 2026 (read-only verification, THL SP-07 at Millar Western, Flagstone Foods and Twin
Rivers): the MDR definition routed isBehavioralMonitoringValid, isEDRDeployed, isEPPDeployed and
isEPPConfigured to epp_transform.py through getLicenseStatus (GET
/installation-tokens/entities/customer-settings/v1). That body has one settings record under
"resources", which the device loop counted as one unprotected host, so every coverage key read False
("0 of 1 hosts"), isEPPConfigured read True, and isBehavioralMonitoringValid (never emitted) failed
with the whole response as its value.

epp_transform.py: empty, error, customer-settings and host-ID-list bodies are Unevaluated (every key
None, dataCollection error); a real host list still measures. crowdstrike-falcon/
isBehavioralMonitoringValid.py (where the fixed definition routes the key, via
getPreventionPolicies): empty, error and non-policy bodies are Unevaluated; real policies still
measure, and flipping the behavioral settings flips the answer."""
import importlib.util
import json
import pathlib

HERE = pathlib.Path(__file__).resolve().parent
FALCON = HERE.parent / "crowdstrike-falcon"


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


EPP = load(HERE / "epp_transform.py", "cs_epp_transform_routing")
BEH = load(FALCON / "isBehavioralMonitoringValid.py", "cs_falcon_behavioral_routing")

AUTH_401 = {"errors": [{"code": 401, "message": "access denied, authorization failed"}], "resources": [], "meta": {}}
AUTH_403 = {"errors": [{"code": 403, "message": "access denied, authorization failed"}], "resources": [], "meta": {}}
# GET /installation-tokens/entities/customer-settings/v1, the body getLicenseStatus returns
CUSTOMER_SETTINGS = {"meta": {"query_time": 0.01, "powered_by": "csam", "trace_id": "t"},
                     "resources": [{"max_active_tokens": 0, "tokens_required": False}], "errors": []}
# GET /devices/queries/devices/v1 (getProtectedHosts): host IDs, not host records
HOST_IDS = {"meta": {"pagination": {"total": 2}}, "resources": ["a1", "b2"], "errors": []}
NO_EVIDENCE = ({}, None, [], "", "not json", AUTH_401, AUTH_403, CUSTOMER_SETTINGS, HOST_IDS,
               {"meta": {}, "resources": [], "errors": []}, {"statusCode": 500, "message": "boom"})


def device(prevention="True", response="True", status="normal"):
    return {"device_id": "d", "hostname": "h", "status": status, "reduced_functionality_mode": "no",
            "agent_version": "7.20", "last_seen": "2026-10-02T05:00:00Z", "product_type_desc": "Workstation",
            "device_policies": {"prevention": {"applied": prevention, "policy_id": "p"},
                                "remote_response": {"applied": response, "policy_id": "r"}}}


def hosts(devices):
    return {"meta": {"pagination": {"total": str(len(devices))}}, "resources": devices, "errors": []}


def epp(payload):
    out = EPP.transform(payload)
    return out["transformedResponse"], out["additionalInfo"]["dataCollection"]["status"]


def test_customer_settings_body_is_unevaluated_not_zero_of_one_hosts():
    result, collection = epp(CUSTOMER_SETTINGS)
    assert collection == "error"
    for key in ("isEDRDeployed", "isEPPDeployed", "isEPPConfigured", "isMDRConfigured",
                "isBehavioralMonitoringValid", "isPatchManagementEnabled", "isRemovableMediaControlled"):
        assert key in result and result[key] is None, key


def test_no_evidence_bodies_never_answer_true_or_false():
    for payload in NO_EVIDENCE:
        result, collection = epp(payload)
        assert collection == "error", payload
        assert all(value is None for value in result.values()), (payload, result)


def test_string_body_of_a_real_host_list_still_measures():
    result, collection = epp(json.dumps(hosts([device() for _ in range(10)])))
    assert collection == "success"
    assert result["isEDRDeployed"] is True and result["isMDRConfigured"] is True


def test_real_host_list_measures_and_discriminates():
    good, _ = epp(hosts([device() for _ in range(20)]))
    bad, _ = epp(hosts([device(prevention="False", response="False", status="offline") for _ in range(20)]))
    assert (good["isEDRDeployed"], good["isEPPDeployed"], good["isEPPConfigured"]) == (True, True, True)
    assert (bad["isEDRDeployed"], bad["isEPPDeployed"]) == (False, False)
    assert good["isMDRConfigured"] is True and bad["isMDRConfigured"] is False


def test_real_unpaged_host_fixture_is_a_measurement():
    body = json.loads((FALCON / "fixtures" / "falcon_hosts_sensor_update_real_2026-09-25.json").read_text())
    result, collection = epp(body)
    assert collection == "success"
    assert isinstance(result["isEDRDeployed"], bool)


def policy(enabled=True, groups=1, behavioral=True):
    return {"id": "p", "name": "Workstations", "platform_name": "Windows", "enabled": enabled,
            "groups": [{"id": "g%d" % n} for n in range(groups)],
            "prevention_settings": [{"name": "Exploit Mitigation", "settings": [
                {"id": "HardwareEnhancedExploitDetection", "name": "Hardware-Enhanced Exploit Detection",
                 "type": "toggle", "value": {"enabled": behavioral}}]}]}


def beh(payload):
    out = BEH.transform(payload)
    return out["transformedResponse"]["isBehavioralMonitoringValid"], out["additionalInfo"]["dataCollection"]["status"]


def test_behavioral_no_evidence_is_unevaluated():
    for payload in NO_EVIDENCE + ({"resources": [{"unrelated": 1}]},):
        assert beh(payload) == (None, "error"), payload


def test_behavioral_real_shape_measures_and_flips():
    assert beh({"resources": [policy()], "errors": [], "meta": {}}) == (True, "success")
    assert beh({"resources": [policy(behavioral=False)], "errors": [], "meta": {}}) == (False, "success")
    assert beh({"resources": [policy(enabled=False)], "errors": [], "meta": {}}) == (False, "success")
    assert beh({"resources": [policy(groups=0)], "errors": [], "meta": {}}) == (False, "success")
    assert beh(json.dumps({"resources": [policy()], "errors": []})) == (True, "success")


def test_behavioral_real_policy_fixture_is_a_measurement():
    body = json.loads((FALCON / "fixtures" / "falcon_complete_prevention_policies_real_2026-09-25.json").read_text())
    value, collection = beh(body)
    assert collection == "success" and isinstance(value, bool)
