"""CrowdStrike Falcon isEDRDeployed / isEPPDeployed: a read that proves nothing is Unevaluated, not False.

Before this change both files answered False (a failed check) for an error body, an empty body and
a partial read, and isEPPDeployed answered True for any body with one record under "resources",
including the customer-settings body of getLicenseStatus. A failed read is not a missing sensor.

Now: no body, a body that is not JSON, an error at any wrapper level, a body with no Falcon host
records, and a partial read that would have said False all return the key as None with a
dataCollection error and the reason. Real, complete host data measures exactly as before, and a
partial read that already shows a streaming sensor still answers True (hosts not read cannot undo
a host that was read).

All host data here is synthetic ("estate A")."""
import importlib.util
import json
import pathlib
from datetime import datetime, timedelta

import pytest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]


# Fresh, so the 15-day reporting window never ages these synthetic hosts out.
RECENT = (datetime.utcnow() - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")

def load(name):
    spec = importlib.util.spec_from_file_location("cs_falcon_" + name + "_fail_closed", HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


EDR = load("isEDRDeployed")
EPP = load("isEPPDeployed")


# ---------------------------------------------------------------- synthetic estate A, real Falcon shapes

def host(n, sensor_update=True, rfm="no", agent_version="7.40.21309.0", last_seen=RECENT):
    """A host record as GET /devices/entities/devices/v2 returns it (synthetic estate A)."""
    policies = {"prevention": {"policy_id": "prev-a", "applied": True}}
    if sensor_update:
        policies["sensor_update"] = {"policy_id": "su-a", "applied": True, "uninstall_protection": "ENABLED"}
    record = {"device_id": "estate-a-dev-%04d" % n, "hostname": "estate-a-host-%04d" % n,
              "status": "normal", "platform_name": "Windows", "product_type_desc": "Workstation",
              "reduced_functionality_mode": rfm, "device_policies": policies, "last_seen": last_seen}
    if agent_version is not None:
        record["agent_version"] = agent_version
    return record


def hosts_body(records, total=None, **pagination):
    page = {"offset": 0, "limit": 5000, "total": len(records) if total is None else total}
    page.update(pagination)
    return {"meta": {"query_time": 0.12, "pagination": page, "powered_by": "device-api", "trace_id": "estate-a"},
            "resources": records, "errors": []}


def scroll_body(count, total=None, **pagination):
    """GET /devices/queries/devices-scroll/v1: host IDs plus the tenant total."""
    page = {"offset": "", "limit": 5000, "total": count if total is None else total}
    page.update(pagination)
    return {"meta": {"query_time": 0.05, "pagination": page, "powered_by": "device-api"},
            "resources": ["%032x" % (0xa0 + i) for i in range(count)], "errors": []}


# GET /installation-tokens/entities/customer-settings/v1, the body getLicenseStatus returns
CUSTOMER_SETTINGS = {"meta": {"query_time": 0.01, "powered_by": "csam", "trace_id": "estate-a"},
                     "resources": [{"max_active_tokens": 0, "tokens_required": False}], "errors": []}
AUTH_401 = {"meta": {}, "resources": [], "errors": [{"code": 401, "message": "access denied, invalid bearer token"}]}
AUTH_403 = {"meta": {}, "resources": None, "errors": [{"code": 403, "message": "access denied, authorization failed"}]}


def run(module, key, payload):
    out = module.transform(payload)
    info = out["additionalInfo"]
    return out["transformedResponse"][key], info


def assert_unevaluated(module, key, payload, reason_contains=None):
    value, info = run(module, key, payload)
    assert value is None, (key, payload if not isinstance(payload, dict) else sorted(payload))
    assert info["dataCollection"]["status"] == "error"
    assert info["dataCollection"]["errors"], "an Unevaluated read must carry a reason"
    assert info["evaluation"]["failReasons"] == info["dataCollection"]["errors"]
    if reason_contains:
        assert reason_contains in info["dataCollection"]["errors"][0], info["dataCollection"]["errors"][0]
    return info


BOTH = [(EDR, "isEDRDeployed"), (EPP, "isEPPDeployed")]


# ---------------------------------------------------------------- real-shape host data: verdicts unchanged

def test_edr_real_shape_estate_passes():
    body = hosts_body([host(i) for i in range(40)] + [host(40, sensor_update=False)])
    value, info = run(EDR, "isEDRDeployed", body)
    assert value is True
    assert info["dataCollection"]["status"] == "success"
    assert info["transformation"]["inputSummary"] == {"totalDevices": 41, "deployedCount": 40, "rfmCount": 0}
    assert info["evaluation"]["additionalFindings"] == []


def test_edr_one_streaming_host_is_enough():
    body = hosts_body([host(0)] + [host(i, sensor_update=False) for i in range(1, 30)])
    assert run(EDR, "isEDRDeployed", body)[0] is True


@pytest.mark.parametrize("flip", ["no_sensor_update", "rfm_true_bool", "rfm_true_str", "no_agent_version"])
def test_edr_flipped_complete_estate_fails(flip):
    if flip == "no_sensor_update":
        records = [host(i, sensor_update=False) for i in range(25)]
    elif flip == "rfm_true_bool":
        records = [host(i, rfm=True) for i in range(25)]
    elif flip == "rfm_true_str":
        records = [host(i, rfm="true") for i in range(25)]
    else:
        records = [host(i, agent_version=None) for i in range(25)]
    value, info = run(EDR, "isEDRDeployed", hosts_body(records))
    assert value is False, flip
    assert info["dataCollection"]["status"] == "success"
    assert info["evaluation"]["failReasons"][0].startswith("None of the 25 devices")


def test_edr_rfm_reporting_is_unchanged():
    body = hosts_body([host(0), host(1, rfm=True), host(2, rfm="True")])
    out = EDR.transform(body)
    assert out["transformedResponse"] == {"isEDRDeployed": True, "totalDevices": 3, "deployedCount": 1,
                                          "reducedFunctionalityModeCount": 2}


def test_edr_without_pagination_meta_measures_as_before():
    body = {"resources": [host(i, sensor_update=False) for i in range(3)], "errors": []}
    assert run(EDR, "isEDRDeployed", body)[0] is False
    body = {"resources": [host(0)], "errors": []}
    assert run(EDR, "isEDRDeployed", body)[0] is True


@pytest.mark.parametrize("total", [130, "130"])
def test_epp_real_shape_scroll_passes(total):
    out = EPP.transform(scroll_body(130, total=total))
    assert out["transformedResponse"] == {"isEPPDeployed": True, "totalDevices": 130}
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"
    assert out["additionalInfo"]["evaluation"]["passReasons"][0].startswith("meta.pagination.total reports 130")


def test_epp_host_records_and_no_pagination_count_the_page():
    out = EPP.transform({"resources": [host(i) for i in range(7)], "errors": []})
    assert out["transformedResponse"] == {"isEPPDeployed": True, "totalDevices": 7}


def test_json_string_bodies_measure_like_dicts():
    edr_body = hosts_body([host(0), host(1, sensor_update=False)])
    assert run(EDR, "isEDRDeployed", json.dumps(edr_body))[0] is True
    assert run(EDR, "isEDRDeployed", json.dumps(hosts_body([host(0, sensor_update=False)])))[0] is False
    assert run(EPP, "isEPPDeployed", json.dumps(scroll_body(5)).encode("utf-8"))[0] is True


@pytest.mark.parametrize("wrapper", ["api_response", "response", "result", "apiResponse", "Output"])
def test_clean_platform_wrappers_are_still_peeled(wrapper):
    assert run(EDR, "isEDRDeployed", {wrapper: hosts_body([host(0)])})[0] is True
    assert run(EDR, "isEDRDeployed", {wrapper: {"response": hosts_body([host(0, sensor_update=False)])}})[0] is False
    assert run(EPP, "isEPPDeployed", {wrapper: scroll_body(3)})[0] is True


def test_enriched_input_measures_its_data():
    validation = {"status": "valid", "errors": [], "warnings": []}
    out = EDR.transform({"data": hosts_body([host(0)]), "validation": validation})
    assert out["transformedResponse"]["isEDRDeployed"] is True
    assert out["additionalInfo"]["validation"]["status"] == "valid"
    assert run(EPP, "isEPPDeployed", {"data": scroll_body(2), "validation": validation})[0] is True


# ---------------------------------------------------------------- nothing to measure: Unevaluated

@pytest.mark.parametrize("module,key", BOTH)
@pytest.mark.parametrize("payload", [None, {}, [], "", b"", "   ", "not json", b"\xff\xfe",
                                     {"meta": {}, "resources": [], "errors": []}, {"resources": None},
                                     {"meta": {"pagination": {"total": 0}}, "resources": [], "errors": []},
                                     [host(0)], 42, True])
def test_empty_none_and_non_json_are_unevaluated(module, key, payload):
    assert_unevaluated(module, key, payload)


@pytest.mark.parametrize("module,key", BOTH)
def test_customer_settings_body_is_unevaluated(module, key):
    # isEPPDeployed read this body as one enrolled host (True) before this change
    assert_unevaluated(module, key, CUSTOMER_SETTINGS, "customer-settings")
    assert_unevaluated(module, key, {"api_response": CUSTOMER_SETTINGS}, "customer-settings")


def test_edr_host_id_list_is_not_host_records():
    assert_unevaluated(EDR, "isEDRDeployed", scroll_body(4), "no Falcon host records")


def test_epp_zero_total_with_records_is_inconsistent():
    assert_unevaluated(EPP, "isEPPDeployed", scroll_body(3, total=0), "inconsistent")


# ---------------------------------------------------------------- error bodies, at every wrapper level

ERRORS = [
    ("errors list", AUTH_401),
    ("errors list, resources null", AUTH_403),
    ("errors list beside real hosts", dict(hosts_body([host(0)]), errors=[{"code": 500, "message": "partial failure"}])),
    ("error flag", {"error": True, "errorMessage": "token expired"}),
    ("error string", {"error": "invalid_client"}),
    ("errorType", {"errorType": "ConnectionError", "errorMessage": "timed out"}),
    ("statusCode 500", {"statusCode": 500, "message": "boom"}),
    ("statusCode '403' string", {"statusCode": "403", "body": "forbidden"}),
    ("status_code 429", {"status_code": 429, "resources": [host(0)]}),
]


@pytest.mark.parametrize("module,key", BOTH)
@pytest.mark.parametrize("label,error", ERRORS, ids=[e[0] for e in ERRORS])
def test_error_at_top_level_is_unevaluated(module, key, label, error):
    assert_unevaluated(module, key, error, "CrowdStrike returned")


@pytest.mark.parametrize("module,key", BOTH)
@pytest.mark.parametrize("wrapper", ["api_response", "response", "result", "apiResponse", "Output"])
def test_error_inside_each_wrapper_is_unevaluated(module, key, wrapper):
    assert_unevaluated(module, key, {wrapper: AUTH_401}, "access denied")
    assert_unevaluated(module, key, {"api_response": {wrapper: AUTH_401}}, "access denied")
    assert_unevaluated(module, key, {"api_response": {"response": {wrapper: {"error": True, "errorMessage": "x"}}}}, "x")


@pytest.mark.parametrize("module,key", BOTH)
@pytest.mark.parametrize("flag", [{"error": True, "errorMessage": "upstream failed"},
                                  {"errors": [{"code": 502, "message": "upstream failed"}]},
                                  {"statusCode": 502, "message": "upstream failed"}])
def test_wrapper_carrying_an_error_is_never_peeled_past(module, key, flag):
    good = hosts_body([host(i) for i in range(5)]) if module is EDR else scroll_body(5)
    for depth in range(3):
        payload = good
        for level in range(depth + 1):
            payload = {"response": payload}
        payload.update(flag)
        assert_unevaluated(module, key, payload)
        nested = {"api_response": dict(flag, response=good)}
        assert_unevaluated(module, key, nested)


@pytest.mark.parametrize("module,key", BOTH)
def test_error_in_enriched_wrapper_or_data_is_unevaluated(module, key):
    good = hosts_body([host(0)]) if module is EDR else scroll_body(1)
    validation = {"status": "valid", "errors": [], "warnings": []}
    assert_unevaluated(module, key, {"data": good, "validation": validation, "error": True, "errorMessage": "x"})
    assert_unevaluated(module, key, {"data": AUTH_401, "validation": validation}, "access denied")
    assert_unevaluated(module, key, {"data": {}, "validation": validation})


# ---------------------------------------------------------------- partial and truncated reads

@pytest.mark.parametrize("partial", ["total_above_read", "total_above_read_str", "truncated_flag_top",
                                     "truncated_flag_meta", "truncated_flag_wrapper", "is_max_pages_merge",
                                     "after_token", "next_token", "nextPage_top"])
def test_edr_partial_read_never_answers_false(partial):
    records = [host(i, sensor_update=False) for i in range(10)]
    if partial == "total_above_read":
        body = hosts_body(records, total=250)
    elif partial == "total_above_read_str":
        body = hosts_body(records, total="250")
    elif partial == "truncated_flag_top":
        body = dict(hosts_body(records), paginationTruncated=True)
    elif partial == "truncated_flag_meta":
        body = hosts_body(records)
        body["meta"]["paginationTruncated"] = "true"
    elif partial == "truncated_flag_wrapper":
        body = {"api_response": hosts_body(records), "paginationTruncated": True}
    elif partial == "is_max_pages_merge":
        # Integration-Service at maxPages: first page's block kept, next cleared, truncated + scannedCount
        body = hosts_body(records, total=10, next=None, truncated=True, scannedCount=10)
    elif partial == "after_token":
        body = hosts_body(records, after="estate-a-scroll-token")
    elif partial == "next_token":
        body = hosts_body(records, next="estate-a-next")
    else:
        body = dict(hosts_body(records), nextPage="https://api.example.invalid/devices?page=2")
    info = assert_unevaluated(EDR, "isEDRDeployed", body, "partial")
    assert info["transformation"]["inputSummary"]["deployedCount"] == 0


def test_edr_partial_read_that_shows_a_streaming_sensor_still_passes():
    body = hosts_body([host(0)] + [host(i, sensor_update=False) for i in range(1, 10)], total=900,
                      after="estate-a-scroll-token")
    value, info = run(EDR, "isEDRDeployed", body)
    assert value is True
    assert info["dataCollection"]["status"] == "success"
    assert info["evaluation"]["additionalFindings"][0].startswith("Partial read")


def test_edr_complete_integration_service_merge_still_fails():
    # every page read: the first page's block is kept with the tenant total and next cleared
    body = hosts_body([host(i, sensor_update=False) for i in range(12)], total=12, next=None)
    assert run(EDR, "isEDRDeployed", body)[0] is False


@pytest.mark.parametrize("blank", ["", None, False, "null"])
def test_blank_next_tokens_are_not_partial(blank):
    body = hosts_body([host(0, sensor_update=False)], after=blank, next=blank)
    assert run(EDR, "isEDRDeployed", body)[0] is False


def test_epp_partial_page_reports_the_tenant_total():
    # devices-scroll returns one page of IDs and the tenant total; the total is the measurement
    body = scroll_body(100, total=1517, next="estate-a-next")
    out = EPP.transform(body)
    assert out["transformedResponse"] == {"isEPPDeployed": True, "totalDevices": 1517}
    assert out["additionalInfo"]["evaluation"]["additionalFindings"][0].startswith("Partial read")
    truncated = dict(scroll_body(10, total=10), paginationTruncated=True)
    assert run(EPP, "isEPPDeployed", truncated)[0] is True


def test_epp_never_answers_false():
    probes = [None, {}, AUTH_401, CUSTOMER_SETTINGS, scroll_body(0), scroll_body(3, total=0),
              hosts_body([host(0, sensor_update=False)]), {"statusCode": 500}]
    for probe in probes:
        assert run(EPP, "isEPPDeployed", probe)[0] is not False, probe


# ---------------------------------------------------------------- transformation errors

class Exploding(dict):
    def get(self, *args, **kwargs):
        raise RuntimeError("estate-a synthetic failure")


@pytest.mark.parametrize("module,key", BOTH)
def test_transformation_error_is_unevaluated(module, key):
    info = assert_unevaluated(module, key, Exploding(resources=[host(0)]), "Transformation error")
    assert info["transformation"]["status"] == "error"
    assert info["transformation"]["errors"][0].startswith("Transformation error")


# ---------------------------------------------------------------- the production sandbox

def test_both_files_compile_and_run_in_the_restricted_sandbox():
    import sys
    sys.path.insert(0, str(ROOT / "tools"))
    try:
        import restricted_sandbox
    except ImportError:  # RestrictedPython not installed locally; CI's contract job compiles every file
        return
    edr = restricted_sandbox.load((HERE / "isEDRDeployed.py").read_text())["transform"]
    epp = restricted_sandbox.load((HERE / "isEPPDeployed.py").read_text())["transform"]
    assert edr(hosts_body([host(0)]))["transformedResponse"]["isEDRDeployed"] is True
    assert edr(hosts_body([host(0, sensor_update=False)]))["transformedResponse"]["isEDRDeployed"] is False
    assert edr(hosts_body([host(0, sensor_update=False)], total=50))["transformedResponse"]["isEDRDeployed"] is None
    assert epp(scroll_body(3))["transformedResponse"]["isEPPDeployed"] is True
    for probe in (None, {}, AUTH_401, CUSTOMER_SETTINGS, {"response": dict(AUTH_403, error=True)}):
        assert edr(probe)["transformedResponse"]["isEDRDeployed"] is None
        assert epp(probe)["transformedResponse"]["isEPPDeployed"] is None


# A list of bare strings that are not Falcon device IDs (32 hex characters) is a misrouted ID-list body.
@pytest.mark.parametrize("ids", [
    ["ldt:0000000000000000000000000000000a:1234"],             # detection ids
    ["0000000000000000000000000000000a_cve-2024-0001"],         # vulnerability instance ids
    ["estate-a-group-1", "estate-a-group-2"],                   # non-hex names
    ["0123456789abcdef"],                                       # too short
])
def test_epp_misrouted_id_list_is_unevaluated(ids):
    out = EPP.transform({"meta": {"pagination": {"total": len(ids)}}, "resources": ids, "errors": []})
    assert out["transformedResponse"]["isEPPDeployed"] is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"
    assert "not Falcon device IDs" in " ".join(out["additionalInfo"]["dataCollection"]["errors"])


def test_epp_device_ids_are_counted_in_either_case():
    ids = ["%032x" % (0xb0 + i) for i in range(3)] + ["%032X" % 0xc0]
    out = EPP.transform({"meta": {"pagination": {"total": 4}}, "resources": ids, "errors": []})
    assert out["transformedResponse"]["isEPPDeployed"] is True


def test_epp_32_hex_policy_ids_are_indistinguishable_from_device_ids_known_limit():
    # Known Low: real Falcon policy ids are also 32 hex, so a misrouted policy-id list reads as hosts. The control is
    # the definition's method binding (devices-scroll for isEPPDeployed), not the id shape. This asserts the honest
    # current behaviour so a future change to it is deliberate.
    policy_ids = ["%032x" % (0xd0 + i) for i in range(2)]
    out = EPP.transform({"meta": {"pagination": {"total": 2}}, "resources": policy_ids, "errors": []})
    assert out["transformedResponse"]["isEPPDeployed"] is True
