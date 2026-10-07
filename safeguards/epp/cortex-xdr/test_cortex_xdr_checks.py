"""Cortex XDR checks on get_endpoint and management_logs bodies shaped like the REST API reference
(reply.total_count / result_count / endpoints). No customer body has been seen."""
import importlib.util
import pathlib

import pytest

HERE = pathlib.Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location("xdr_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def body(total, shown=0):
    return {"reply": {"total_count": total, "result_count": shown, "endpoints": [{"endpoint_id": str(i)} for i in range(shown)]}}


def counts(enrolled=250, connected=240, offline=10, isolated=1):
    return {"enrolled": body(enrolled), "connected": body(connected), "offline": body(offline), "isolated": body(isolated)}


FAIL_CLOSED = [{}, None, "{}", "", {"error": True, "statusCode": 401}, {"hello": "world"},
               {"enrolled": {"reply": {}}, "connected": {"reply": {"result_count": 100, "endpoints": [{}] * 100}}}]
CHECKS = {"isedrdeployed": ("isEDRDeployed", False), "iseppdeployed": ("isEPPDeployed", False),
          "offlinesensorcount": ("offlineSensorCount", None), "isolatedendpointcount": ("isolatedEndpointCount", None),
          "requiredcoveragepercentage": ("requiredCoveragePercentage", None)}


@pytest.mark.parametrize("body_in", FAIL_CLOSED)
@pytest.mark.parametrize("name", sorted(CHECKS))
def test_fail_closed(name, body_in):
    key, bad = CHECKS[name]
    assert load(name)(body_in)[key] is bad


def test_counts_pass_and_flip():
    c = counts()
    assert load("isedrdeployed")(c)["isEDRDeployed"] is True
    assert load("iseppdeployed")(c)["isEPPDeployed"] is True
    assert load("offlinesensorcount")(c)["offlineSensorCount"] == 10
    assert load("isolatedendpointcount")(c)["isolatedEndpointCount"] == 1
    assert load("requiredcoveragepercentage")(c)["requiredCoveragePercentage"] == 96.0
    none = counts(enrolled=0, connected=0, offline=0, isolated=0)
    assert load("isedrdeployed")(none)["isEDRDeployed"] is False
    assert load("iseppdeployed")(none)["isEPPDeployed"] is False
    assert load("requiredcoveragepercentage")(none)["requiredCoveragePercentage"] is None


def test_no_total_count_is_unknown():
    short = {"connected": {"reply": {"result_count": 3, "endpoints": [{}, {}, {}]}}}
    assert load("isedrdeployed")(short)["isEDRDeployed"] is False


def test_audit_log():
    t = load("isapiauditloggingenabled")
    assert t({"reply": {"total_count": 52, "result_count": 1, "data": [{"AUDIT_ID": 1}]}})["isApiAuditLoggingEnabled"] is True
    assert t({"reply": {"result_count": 1, "data": [{"AUDIT_ID": 1}]}})["isApiAuditLoggingEnabled"] is True
    assert t({"reply": {"total_count": 0, "result_count": 0, "data": []}})["isApiAuditLoggingEnabled"] is False
    for b in [{}, None, "{}", {"error": True}, {"reply": {}}]:
        assert t(b)["isApiAuditLoggingEnabled"] is False
