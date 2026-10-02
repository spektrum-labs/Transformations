"""Red Canary MDR transforms fail closed to Unevaluated (2026-10-01).

A Red Canary endpoints read that measured nothing -- an empty body, zero endpoints, a vendor or
platform error, an unrecognised payload, a read cut short -- proves nothing about MDR, so every key
must come back None with dataCollection.status "error" (Token-Service reads that as Unevaluated),
never False or 0.0. The integration pages GET /openapi/v3/endpoints; when a page is rate-limited
part-way through, the platform hands the transformation an empty body with no error on it, and the
old code turned that into "MDR not enabled", "logging not enabled" and "0.0% coverage" findings.

A real measured body still answers, in both shapes: the drilled endpoint LIST Token-Service hands a
legacy transformation, and the {"meta", "links", "data"} envelope.

All fixtures are synthetic: invented hostnames, ids and timestamps on example.test.
"""
import importlib.util
import json
from pathlib import Path

import pytest

HERE = Path(__file__).parent

# file -> the criteria keys it emits
FILES = {
    "isMDREnabled": ["isMDREnabled", "isMDRConfigured"],
    "isMDRLoggingEnabled": ["isMDRLoggingEnabled"],
    "requiredCoveragePercentage": ["requiredCoveragePercentage"],
    "isendpointcoveragevalid": ["isEndpointCoverageValid"],
    "iscloudmonitoringenabled": ["isCloudMonitoringEnabled"],
    "confirmedlicensepurchased": ["confirmedLicensePurchased"],
    "isalertingconfigured": ["isAlertingConfigured"],
}
ENDPOINT_FILES = ["isMDREnabled", "isMDRLoggingEnabled", "requiredCoveragePercentage",
                  "isendpointcoveragevalid", "iscloudmonitoringenabled"]

NO_EVIDENCE = {
    "null": None,
    "empty_dict": {},
    "empty_list": [],
    "empty_string_json": "{}",
    "not_json": "<html><body>502 Bad Gateway</body></html>",
    "auth_401": {"statusCode": 401, "error": "Unauthorized"},
    "auth_401_snake": {"status_code": 401, "error": "Unauthorized"},
    "auth_401_nested": {"error": {"statusCode": 401, "message": "Unauthorized"}},
    "auth_403": {"statusCode": 403, "error": "Forbidden"},
    "rate_limited": {"status_code": 429, "error": "Too Many Requests"},
    "rate_limited_string_code": {"status_code": "429", "_response_data": {}},
    "vendor_errors_list": {"errors": [{"title": "Unauthorized", "detail": "API token is invalid"}]},
    "platform_error": {"status": "Error", "message": "upstream call failed"},
    "unrelated": {"hello": "world"},
    "unrelated_nested": {"foo": {"bar": [1, 2, 3]}},
    "data_null": {"data": None, "validation": {"status": "unknown", "errors": [], "warnings": []}},
}


def endpoint(i, monitoring="monitored", status="online", decommissioned="False"):
    return {"type": "Endpoint", "id": str(5000 + i),
            "attributes": {"display_identifier": "host-%03d.example.test" % i, "hostname": "host-%03d" % i,
                           "monitoring_status": monitoring, "endpoint_status": status,
                           "is_decommissioned": decommissioned, "platform": "Windows",
                           "last_checkin_time": "2026-09-30T12:00:00Z"}}


def envelope(records, total=None):
    return {"meta": {"api_version": "v3.0", "total_items": str(len(records) if total is None else total)},
            "links": {"self": "https://tenant.example.test/openapi/v3/endpoints?page=3", "next": "None"},
            "data": records}


FLEET = [endpoint(i) for i in range(97)] + [endpoint(100 + i, "unmonitored", "suspended") for i in range(3)]
UNMONITORED = [endpoint(i, "unmonitored", "suspended") for i in range(40)]
AUDIT_LOGS = {"meta": {"api_version": "v3.0", "total_items": "120"},
              "data": [{"type": "AuditLog", "id": str(i),
                        "attributes": {"action": "user.login", "created_at": "2026-09-30T12:00:00Z"}}
                       for i in range(50)]}
ALERTING = {"triggers": {"meta": {"total_items": "2"}, "data": [{"id": "1", "active": True}, {"id": "2", "active": False}]},
            "playbooks": {"meta": {"total_items": "1"}, "data": [{"id": "9", "active": True}]}}
ALERTING_NONE = {"triggers": {"meta": {"total_items": "0"}, "data": []},
                 "playbooks": {"meta": {"total_items": "0"}, "data": []}}


def load(name):
    spec = importlib.util.spec_from_file_location("rc_fc_" + name, HERE / (name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


MODS = {name: load(name) for name in FILES}


def run(name, payload):
    out = MODS[name].transform(json.loads(json.dumps(payload)) if payload is not None else None)
    return out["transformedResponse"], out["additionalInfo"]["dataCollection"]


def assert_unevaluated(name, payload):
    tr, dc = run(name, payload)
    for key in FILES[name]:
        assert tr.get(key) is None, (name, key, tr)
    assert dc["status"] == "error" and dc["errors"], (name, dc)


# ---- no evidence -> Unevaluated, every file ---------------------------------------------------

@pytest.mark.parametrize("name", sorted(FILES))
@pytest.mark.parametrize("case", sorted(NO_EVIDENCE))
def test_no_evidence_is_unevaluated(name, case):
    assert_unevaluated(name, NO_EVIDENCE[case])


# ---- the defect: zero endpoints -----------------------------------------------------------------

@pytest.mark.parametrize("name", ENDPOINT_FILES)
@pytest.mark.parametrize("payload", [[], envelope([]), envelope([], total=0), {"data": []}],
                         ids=["drilled_empty_list", "envelope_zero", "envelope_zero_explicit", "bare_data"])
def test_zero_endpoints_is_unevaluated_not_a_finding(name, payload):
    tr, dc = run(name, payload)
    for key in FILES[name]:
        assert tr.get(key) is None, (name, key, tr)
        assert tr.get(key) is not False and tr.get(key) != 0.0
    assert dc["status"] == "error"


# ---- truncated or unrecognised reads ------------------------------------------------------------

@pytest.mark.parametrize("name", ENDPOINT_FILES)
def test_enveloped_read_shorter_than_its_census_is_unevaluated(name):
    # 100 records returned of 1151 reported: pages are missing
    assert_unevaluated(name, envelope(FLEET, total=1151))


@pytest.mark.parametrize("name", ENDPOINT_FILES)
def test_platform_truncation_flag_is_unevaluated(name):
    body = envelope(FLEET)
    body["meta"]["truncated"] = True
    assert_unevaluated(name, body)


@pytest.mark.parametrize("name", ENDPOINT_FILES)
def test_read_at_the_page_cap_is_unevaluated(name):
    capped = [endpoint(i) for i in range(MODS[name].ENDPOINT_READ_CAP)]
    assert_unevaluated(name, capped)


@pytest.mark.parametrize("name", ENDPOINT_FILES)
def test_records_that_are_not_endpoints_are_unevaluated(name):
    assert_unevaluated(name, [{"x": 1}, {"y": 2}])
    assert_unevaluated(name, {"data": [1, 2, 3]})


# ---- a real measurement still answers -----------------------------------------------------------

@pytest.mark.parametrize("shape", ["list", "envelope", "apiResponse_wrap", "json_string"])
def test_measured_fleet_answers(shape):
    def shaped(records):
        if shape == "list":
            return records
        if shape == "envelope":
            return envelope(records)
        if shape == "apiResponse_wrap":
            return {"apiResponse": envelope(records)}
        return json.dumps(envelope(records))

    tr, dc = run("isMDREnabled", shaped(FLEET))
    assert dc["status"] == "success"
    assert tr["isMDREnabled"] is True and tr["isMDRConfigured"] is True and tr["totalEndpoints"] == 100
    tr, dc = run("isMDRLoggingEnabled", shaped(FLEET))
    assert dc["status"] == "success" and tr["isMDRLoggingEnabled"] is True
    assert tr["totalEnrolledEndpoints"] == 100
    tr, dc = run("requiredCoveragePercentage", shaped(FLEET))
    assert dc["status"] == "success" and tr["requiredCoveragePercentage"] == 100.0
    tr, dc = run("isendpointcoveragevalid", shaped(FLEET))
    assert dc["status"] == "success" and tr["isEndpointCoverageValid"] is True
    assert (tr["totalEndpoints"], tr["monitoredEndpoints"], tr["unmonitoredEndpoints"]) == (100, 97, 3)
    tr, dc = run("iscloudmonitoringenabled", shaped(FLEET[:97]))
    assert dc["status"] == "success" and tr["isCloudMonitoringEnabled"] is True


def test_measured_bad_posture_still_answers_false():
    tr, dc = run("isMDREnabled", UNMONITORED)
    assert dc["status"] == "success" and tr["isMDRConfigured"] is False and tr["mdrMonitoredPercentage"] == 0.0
    tr, dc = run("isendpointcoveragevalid", envelope(UNMONITORED))
    assert dc["status"] == "success" and tr["isEndpointCoverageValid"] is False
    tr, dc = run("isalertingconfigured", ALERTING_NONE)
    assert dc["status"] == "success" and tr["isAlertingConfigured"] is False


def test_string_counts_no_longer_raise():
    # meta.total_items arrives as a string; isMDRLoggingEnabled used to raise on "> 0"
    tr, dc = run("isMDRLoggingEnabled", envelope(FLEET))
    assert dc["status"] == "success" and tr["isMDRLoggingEnabled"] is True


def test_decommissioned_string_flag_is_counted():
    records = FLEET[:10] + [endpoint(300 + i, "unmonitored", "offline", "True") for i in range(4)]
    tr, _ = run("isMDRLoggingEnabled", records)
    assert (tr["activeEndpointCount"], tr["decommissionedEndpointCount"]) == (10, 4)


def test_license_and_alerting_measured_reads_answer():
    tr, dc = run("confirmedlicensepurchased", AUDIT_LOGS)
    assert dc["status"] == "success" and tr["confirmedLicensePurchased"] is True
    tr, dc = run("isalertingconfigured", ALERTING)
    assert dc["status"] == "success" and tr["isAlertingConfigured"] is True


def test_license_empty_audit_log_is_unevaluated():
    assert_unevaluated("confirmedlicensepurchased", {"meta": {"total_items": "0"}, "data": []})


def test_alerting_one_section_unread_is_unevaluated_unless_the_other_proves_it():
    # triggers read cleanly and empty, playbooks read failed: nothing proven either way
    assert_unevaluated("isalertingconfigured", {"triggers": {"data": []}, "playbooks": None})
    assert_unevaluated("isalertingconfigured",
                       {"triggers": {"data": []}, "playbooks": {"status_code": 429, "error": "Too Many Requests"}})
    # a configured trigger is evidence on its own, whatever happened to the playbooks read
    tr, dc = run("isalertingconfigured", {"triggers": {"data": [{"id": "1", "active": True}]}, "playbooks": None})
    assert dc["status"] == "success" and tr["isAlertingConfigured"] is True


def test_transformation_exception_is_unevaluated(monkeypatch):
    def boom(*args, **kwargs):
        raise ValueError("synthetic failure")
    for name in ENDPOINT_FILES:
        monkeypatch.setattr(MODS[name], "endpoint_census", boom)
        assert_unevaluated(name, FLEET)
