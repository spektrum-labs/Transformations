"""Red Canary requiredCoveragePercentage reads monitoring_status (2026-10-02).

The old transform divided the listed endpoints by an "expected fleet" it never found, fell back
to the listed count, and read 100% at every tenant -- including ones where Red Canary itself
reported half the fleet unmonitored. Coverage is now monitored / live (not decommissioned)
endpoints as a whole number, rounded down. Empty, error and partial reads are Unevaluated
(None with dataCollection.status "error"), never 100 and never 0.

All fixtures are synthetic: invented hostnames, ids and timestamps on example.test.
"""
import importlib.util
import json
from pathlib import Path

import pytest

HERE = Path(__file__).parent
KEY = "requiredCoveragePercentage"


def load():
    spec = importlib.util.spec_from_file_location("rc_cov", HERE / "requiredCoveragePercentage.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


MOD = load()


def run(payload):
    out = MOD.transform(json.loads(json.dumps(payload)) if payload is not None else None)
    return out["transformedResponse"], out["additionalInfo"]


def endpoint(i, monitoring="monitored", status="online", decommissioned="False"):
    attrs = {"display_identifier": "host-%03d.example.test" % i, "hostname": "host-%03d" % i,
             "endpoint_status": status, "is_decommissioned": decommissioned,
             "platform": "Windows", "registration_time": "2025-01-10T09:00:00Z",
             "last_checkin_time": "2026-10-01T12:00:00Z"}
    if monitoring is not None:
        attrs["monitoring_status"] = monitoring
    return {"type": "Endpoint", "id": str(7000 + i), "attributes": attrs}


def envelope(records, total=None):
    return {"meta": {"api_version": "v3.0",
                     "total_items": str(len(records) if total is None else total)},
            "links": {"self": "https://tenant.example.test/openapi/v3/endpoints?page=1",
                      "next": "None"},
            "data": records}


def assert_unevaluated(payload, reason_part=None):
    tr, info = run(payload)
    assert tr.get(KEY) is None, tr
    dc = info["dataCollection"]
    assert dc["status"] == "error" and dc["errors"], dc
    if reason_part:
        assert reason_part in dc["errors"][0], dc["errors"]
    return dc["errors"][0]


# ---- empty ------------------------------------------------------------------------------------

@pytest.mark.parametrize("payload", [None, {}, [], "", "{}", envelope([]), {"data": []}],
                         ids=["null", "empty_dict", "empty_list", "empty_string", "empty_json",
                              "envelope_zero", "bare_data_empty"])
def test_empty_is_unevaluated_never_100_or_0(payload):
    assert_unevaluated(payload)


def test_only_decommissioned_is_unevaluated():
    records = [endpoint(i, "unmonitored", "offline", "True") for i in range(4)]
    assert_unevaluated(records, "decommissioned")


# ---- error ------------------------------------------------------------------------------------

@pytest.mark.parametrize("payload", [
    {"statusCode": 401, "error": "Unauthorized"},
    {"status_code": "429", "error": "Too Many Requests"},
    {"errors": [{"title": "Forbidden", "detail": "API token lacks permission"}]},
    {"status": "Error", "message": "upstream call failed"},
    "<html><body>502 Bad Gateway</body></html>",
], ids=["auth_401", "rate_limited", "vendor_errors", "platform_error", "not_json"])
def test_error_is_unevaluated(payload):
    assert_unevaluated(payload)


def test_transformation_exception_is_unevaluated(monkeypatch):
    def boom(*args, **kwargs):
        raise ValueError("synthetic failure")
    monkeypatch.setattr(MOD, "coverage_census", boom)
    assert_unevaluated([endpoint(1)], "Transformation error")


# ---- partial ----------------------------------------------------------------------------------

def test_read_shorter_than_reported_census_is_unevaluated():
    assert_unevaluated(envelope([endpoint(i) for i in range(10)], total=200), "incomplete")


def test_endpoint_without_monitoring_status_is_unevaluated():
    records = [endpoint(i) for i in range(8)] + [endpoint(50, monitoring=None), endpoint(51, monitoring="")]
    reason = assert_unevaluated(records, "monitoring_status")
    assert reason.startswith("2 of 10")


def never_checked_in_endpoint(i):
    """A listed, live endpoint whose sensor never checked in (all state fields empty)."""
    attrs = {"display_identifier": "host-%03d.example.test" % i, "hostname": "host-%03d" % i,
             "monitoring_status": None, "endpoint_status": None, "platform": None,
             "registration_time": None, "last_checkin_time": None, "is_decommissioned": False,
             "sensor": {"type": "Sensor", "id": "sensor-%03d" % i,
                        "attributes": {"registration_time": None, "last_checkin_time": None}}}
    return {"type": "Endpoint", "id": str(9000 + i), "attributes": attrs}


def test_never_checked_in_endpoints_count_as_unmonitored_not_as_a_partial_census():
    records = ([endpoint(i) for i in range(4)] + [endpoint(10 + i, "unmonitored", "suspended") for i in range(19)]
               + [never_checked_in_endpoint(1)])
    tr, info = run(envelope(records))
    assert tr[KEY] == 16, tr  # 4 monitored of 24 live: floor(16.6)
    assert tr["totalEndpoints"] == 24 and tr["monitoredEndpoints"] == 4
    assert tr["neverCheckedInEndpoints"] == 1 and tr["unmonitoredEndpoints"] == 20
    assert info["dataCollection"]["status"] == "success" and not info["dataCollection"]["errors"]
    assert any("never checked in" in r for r in info["evaluation"]["failReasons"])


def test_never_checked_in_endpoints_never_raise_coverage():
    # 95 monitored of 100 live passes a 95 threshold; one more never-registered record drops it to 94
    base = [endpoint(i) for i in range(95)] + [endpoint(200 + i, "unmonitored", "suspended") for i in range(5)]
    assert run(base)[0][KEY] == 95
    assert run(base + [never_checked_in_endpoint(1)])[0][KEY] == 94


def test_all_monitored_plus_a_never_checked_in_endpoint_is_not_100():
    tr, _ = run([endpoint(i) for i in range(9)] + [never_checked_in_endpoint(1)])
    assert tr[KEY] == 90


def test_no_live_endpoint_reporting_a_status_is_unevaluated():
    reason = assert_unevaluated([never_checked_in_endpoint(i) for i in range(3)], "No live endpoint reports")
    assert "3 never checked in" in reason


def test_registered_but_never_checked_in_endpoint_counts_as_unmonitored():
    attrs = never_checked_in_endpoint(2)["attributes"]
    attrs["registration_time"] = "2026-09-11T21:50:50Z"
    tr, _ = run([endpoint(i) for i in range(9)] + [{"type": "Endpoint", "id": "9002", "attributes": attrs}])
    assert tr[KEY] == 90 and tr["neverCheckedInEndpoints"] == 1


def test_endpoint_with_a_check_in_but_no_status_is_still_a_partial_census():
    # it shows a check-in, so its missing monitoring_status is unexplained, not a never-checked-in record
    records = [endpoint(i) for i in range(6)] + [never_checked_in_endpoint(1), endpoint(50, monitoring=None)]
    reason = assert_unevaluated(records, "monitoring_status")
    assert reason.startswith("1 of 8")


def test_non_endpoint_record_in_census_is_unevaluated():
    assert_unevaluated([endpoint(1), endpoint(2), {"foo": "bar"}], "partial")


def test_truncated_flag_is_unevaluated():
    body = envelope([endpoint(i) for i in range(5)])
    body["meta"]["truncated"] = "true"
    assert_unevaluated(body)


# ---- all monitored ----------------------------------------------------------------------------

@pytest.mark.parametrize("shape", ["list", "envelope", "wrapped", "json_string"])
def test_all_monitored_is_100(shape):
    records = [endpoint(i) for i in range(16)]
    payload = {"list": records, "envelope": envelope(records),
               "wrapped": {"apiResponse": envelope(records)},
               "json_string": json.dumps(envelope(records))}[shape]
    tr, info = run(payload)
    assert info["dataCollection"]["status"] == "success"
    assert tr[KEY] == 100 and isinstance(tr[KEY], int)
    assert (tr["monitoredEndpoints"], tr["totalEndpoints"], tr["unmonitoredEndpoints"]) == (16, 16, 0)


def test_decommissioned_are_left_out_of_the_denominator():
    records = [endpoint(i) for i in range(3)] + [endpoint(10 + i, "unmonitored", "offline", "True")
                                                 for i in range(5)]
    tr, info = run(envelope(records))
    assert tr[KEY] == 100 and tr["totalEndpoints"] == 3 and tr["decommissionedEndpoints"] == 5


# ---- partly monitored -------------------------------------------------------------------------

@pytest.mark.parametrize("monitored,total,expected", [
    (111, 200, 55),   # large fleet shape: 55.5% -> 55
    (13, 15, 86),     # mid fleet shape: 86.67% -> 86
    (5, 10, 50),      # small fleet shape
    (46, 50, 92),     # just below a 95 bar: 92% -> 92
    (189, 199, 94),   # 94.97%: rounds DOWN, never up to the 95 bar
    (0, 2, 0),        # measured zero is a real 0, not an empty read
])
def test_partly_monitored_is_whole_number_floor(monitored, total, expected):
    records = [endpoint(i) for i in range(monitored)] + [
        endpoint(1000 + i, "unmonitored", "suspended") for i in range(total - monitored)]
    tr, info = run(envelope(records))
    assert info["dataCollection"]["status"] == "success"
    assert tr[KEY] == expected and isinstance(tr[KEY], int)
    assert tr["unmonitoredEndpoints"] == total - monitored
    if monitored < total:
        assert info["evaluation"]["failReasons"] and info["evaluation"]["recommendations"]


def test_listed_endpoints_are_not_counted_as_covered():
    """The regression: a fleet Red Canary reports mostly unmonitored no longer reads 100."""
    records = [endpoint(i) for i in range(5)] + [endpoint(100 + i, "unmonitored", "offline")
                                                 for i in range(5)]
    tr, _ = run(envelope(records))
    assert tr[KEY] == 50


# ---- real shape -------------------------------------------------------------------------------

def test_real_v3_shape():
    """GET /openapi/v3/endpoints envelope as Token-Service stores it: string counts, string
    booleans, mixed case statuses, decommissioned records, one record per type "Endpoint"."""
    body = {
        "meta": {"api_version": "v3.0", "total_items": "12", "per_page": "50", "page": "1"},
        "links": {"self": "https://acme.my.redcanary.example.test/openapi/v3/endpoints?page=1&per_page=50",
                  "next": "None", "prev": "None"},
        "data": (
            [endpoint(i, "Monitored") for i in range(7)]
            + [endpoint(20 + i, "unmonitored", "suspended") for i in range(3)]
            + [endpoint(40 + i, "unmonitored", "offline", "True") for i in range(2)]
        ),
    }
    tr, info = run(body)
    assert info["dataCollection"]["status"] == "success"
    assert tr[KEY] == 70
    assert (tr["monitoredEndpoints"], tr["unmonitoredEndpoints"], tr["totalEndpoints"],
            tr["decommissionedEndpoints"]) == (7, 3, 10, 2)
    assert info["transformation"]["inputSummary"]["totalItems"] == "12"
