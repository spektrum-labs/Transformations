"""Red Canary isMDRConfigured (isMDREnabled.py) and isEndpointCoverageValid.

isMDRConfigured used to be a copy of isMDREnabled (any endpoint enrolled). It is now the share of
enrolled, non-decommissioned endpoints whose attributes.monitoring_status is "monitored", against a
95% threshold, and None when nothing reports a monitoring_status.

Synthetic bodies in the real v3 shape (GET /openapi/v3/endpoints: fields under "attributes",
booleans and counts as strings). Token-Service drills a legacy transform's input through "data",
so production hands isMDREnabled.py the endpoint LIST; both shapes are tested.
Populated, flipped, empty, None, 401, 403."""
import importlib.util
import json
import pathlib

HERE = pathlib.Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location("rc_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MDR = load("isMDREnabled")
COV = load("isendpointcoveragevalid")
AUTH_401 = {"error": {"code": 401, "message": "Unauthorized"}, "status_code": 401}
AUTH_403 = {"error": {"code": 403, "message": "Forbidden"}, "status_code": 403}


def endpoint(monitoring="monitored", status="online", decommissioned="False"):
    return {"type": "Endpoint", "attributes": {"monitoring_status": monitoring, "endpoint_status": status,
                                               "is_decommissioned": decommissioned, "platform": "Windows"}}


def body(monitored, unmonitored, decommissioned=0):
    data = [endpoint() for _ in range(monitored)]
    data = data + [endpoint("unmonitored", "suspended") for _ in range(unmonitored)]
    data = data + [endpoint("unmonitored", "offline", "True") for _ in range(decommissioned)]
    return {"meta": {"api_version": "v3.0", "total_items": str(len(data))}, "links": {}, "data": data}


def mdr(payload):
    out = MDR.transform(payload)["transformedResponse"]
    return out["isMDRConfigured"], out.get("mdrMonitoredPercentage"), out["isMDREnabled"]


def test_fully_monitored_tenant_is_configured():
    assert mdr(body(96, 0)["data"]) == (True, 100.0, True)


def test_suspended_endpoints_below_threshold_are_not_configured_although_mdr_is_enabled():
    # 80 of 96 monitored, 16 enrolled but unmonitored: enabled, not configured
    assert mdr(body(80, 16)["data"]) == (False, 83.33, True)


def test_threshold_is_inclusive_and_decommissioned_endpoints_do_not_count():
    assert mdr(body(95, 5)["data"])[:2] == (True, 95.0)
    assert mdr(body(94, 6)["data"])[:2] == (False, 94.0)
    assert mdr(body(20, 0, decommissioned=10)["data"])[:2] == (True, 100.0)


def test_list_and_enveloped_shapes_agree():
    assert mdr(body(80, 16)["data"])[:2] == mdr(json.loads(json.dumps(body(80, 16)["data"])))[:2]
    assert mdr({"apiResponse": {"data": body(96, 0)["data"], "meta": {"total_items": 96}}})[:2] == (True, 100.0)


def test_no_evidence_is_unanswered_not_copied_from_enabled():
    for payload in ({}, None, [], AUTH_401, AUTH_403, {"data": [], "meta": {"total_items": 0}}):
        assert mdr(payload)[:2] == (None, None), payload


def test_endpoints_without_monitoring_status_are_unanswered():
    data = [{"type": "Endpoint", "attributes": {"platform": "Windows"}} for _ in range(5)]
    assert mdr(data)[:2] == (None, None)


def cov(payload):
    out = COV.transform(payload)["transformedResponse"]
    return out["isEndpointCoverageValid"], out.get("monitoredEndpoints"), out.get("coveragePercentage")


def test_coverage_reads_nested_monitoring_status_and_meta_total_items():
    assert cov(body(80, 16)) == (True, 80, 83.3)


def test_coverage_no_longer_assumes_monitored_when_status_is_absent():
    data = [{"type": "Endpoint", "attributes": {"platform": "Windows"}} for _ in range(5)]
    assert cov({"data": data, "meta": {"total_items": "5"}})[:2] == (False, 0)
    assert cov(body(0, 12))[:2] == (False, 0)


def test_coverage_no_evidence_is_unevaluated():
    # was "fails" (False): a body that measured nothing is Unevaluated, never a finding
    for payload in ({}, None, [], AUTH_401, AUTH_403):
        assert cov(payload)[0] is None, payload
