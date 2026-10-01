"""Rapid7 MDR (InsightIDR) transforms for the NIST CSF 2.0 bundle keys.

Bodies follow the InsightIDR shapes read live on 2026-10-01 (values synthetic):
- /idr/v2/investigations: {"data": [...], "metadata": {"index", "size", "total_pages", "total_data"}}
- /idr/v1/health-metrics: {"data": [...], "metadata": {...}}; type is in the rrn
  (rrn:agents:<region>:<org>:status:summary, rrn:collection:<region>:<org>:eventsource:...)
- /log_search/management/logsets: {"logsets": [{"name", "logs_info": [...]}]}
Every key must answer True and False from real shapes and None (never True) from no evidence.
"""
import copy
import importlib.util
import json
import pathlib
from datetime import datetime, timedelta

import pytest

HERE = pathlib.Path(__file__).resolve().parent


def load(key):
    spec = importlib.util.spec_from_file_location(key, HERE / (key + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.transform


def value(key, body):
    return load(key)(body)["transformedResponse"][key]


def iso(delta):
    return (datetime.utcnow() - delta).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def investigations(rows, total=None):
    return {"data": rows, "metadata": {"index": 0, "size": 100, "total_pages": 1,
                                       "total_data": len(rows) if total is None else total}}


def inv(responsibility="CUSTOMER", source="ALERT", age_days=3):
    return {"rrn": "rrn:investigation:us:org:investigation:X", "status": "OPEN", "priority": "HIGH",
            "responsibility": responsibility, "source": source, "created_time": iso(timedelta(days=age_days))}


def health(agents=(90, 5, 5), sources=(("RUNNING", 1),)):
    on, off, st = agents
    rows = [{"rrn": "rrn:agents:us:org:status:summary", "online": on, "offline": off, "stale": st, "total": on + off + st}]
    for state, age_h in sources:
        rows.append({"rrn": "rrn:collection:us:org:eventsource:collector:E", "name": "DC", "state": state,
                     "last_active": iso(timedelta(hours=age_h)) if age_h is not None else None, "issue": None})
    return {"data": rows, "metadata": {"index": 0, "size": 100, "total_pages": 1, "total_data": len(rows)}}


def logsets(cloud_logs=2):
    return {"logsets": [
        {"name": "Endpoint Activity", "logs_info": [{"id": "a", "name": "agents"}]},
        {"name": "Cloud Service Activity", "logs_info": [{"id": "c%d" % i, "name": "m365"} for i in range(cloud_logs)]},
        {"name": "Cloud Service Admin Activity", "logs_info": []},
    ]}


NO_EVIDENCE = [{}, "", None, {"status": 401, "message": "Unauthorized"}, {"error": "invalid_token"},
               {"data": [], "metadata": {"total_data": 0}}, {"foo": "bar"}, {"logsets": []},
               {"data": [{"enabled": False}]}, {"message": "Too many requests", "status_code": 429}]
KEYS = ["isMDREnabled", "isAlertingConfigured", "isMDRLoggingEnabled", "isEndpointCoverageValid", "isCloudMonitoringEnabled"]


@pytest.mark.parametrize("key", KEYS)
@pytest.mark.parametrize("body", NO_EVIDENCE)
def test_no_evidence_is_none(key, body):
    assert value(key, body) is None


@pytest.mark.parametrize("key", KEYS)
def test_enriched_input_contract(key):
    body = {"isMDREnabled": investigations([inv("MDR")]), "isAlertingConfigured": investigations([inv()]),
            "isMDRLoggingEnabled": health(), "isEndpointCoverageValid": health(),
            "isCloudMonitoringEnabled": logsets()}[key]
    assert value(key, {"data": body, "validation": {"status": "unknown"}}) is True
    assert value(key, {"result": {"apiResponse": json.dumps(body)}}) is True


def test_mdr_enabled():
    assert value("isMDREnabled", investigations([inv(), inv("MDR")])) is True
    assert value("isMDREnabled", investigations([inv(), inv()])) is False
    # a partial read without MDR cannot prove absence
    assert value("isMDREnabled", investigations([inv(), inv()], total=500)) is None
    assert value("isMDREnabled", investigations([inv("MDR")], total=500)) is True


def test_alerting_configured():
    assert value("isAlertingConfigured", investigations([inv(source="MANUAL"), inv()])) is True
    assert value("isAlertingConfigured", investigations([inv(source="MANUAL")])) is False
    assert value("isAlertingConfigured", investigations([inv(age_days=200)])) is False
    assert value("isAlertingConfigured", investigations([inv(source="MANUAL")], total=900)) is None
    bad_time = inv()
    bad_time["created_time"] = "yesterday"
    assert value("isAlertingConfigured", investigations([bad_time])) is None


def test_logging_enabled():
    assert value("isMDRLoggingEnabled", health(sources=(("RUNNING", 2), ("STOPPED", None)))) is True
    assert value("isMDRLoggingEnabled", health(sources=(("STOPPED", None), ("WARNING", 1)))) is False
    assert value("isMDRLoggingEnabled", health(sources=(("RUNNING", 72),))) is False
    assert value("isMDRLoggingEnabled", health(sources=())) is False
    unknown = health(sources=(("RUNNING", None),))
    assert value("isMDRLoggingEnabled", unknown) is None


def test_endpoint_coverage():
    assert value("isEndpointCoverageValid", health(agents=(70, 25, 5))) is True
    assert value("isEndpointCoverageValid", health(agents=(80, 10, 10))) is True
    assert value("isEndpointCoverageValid", health(agents=(50, 20, 30))) is False
    assert value("isEndpointCoverageValid", health(agents=(0, 0, 0))) is False
    no_summary = health()
    no_summary["data"] = no_summary["data"][1:]
    no_summary["metadata"]["total_data"] = len(no_summary["data"])
    assert value("isEndpointCoverageValid", no_summary) is None
    broken = copy.deepcopy(health())
    broken["data"][0]["online"] = 500
    assert value("isEndpointCoverageValid", broken) is None


def test_cloud_monitoring():
    assert value("isCloudMonitoringEnabled", logsets(2)) is True
    assert value("isCloudMonitoringEnabled", logsets(0)) is False
    only_endpoint = {"logsets": [{"name": "Endpoint Activity", "logs_info": [{"id": "a"}]}]}
    assert value("isCloudMonitoringEnabled", only_endpoint) is False
