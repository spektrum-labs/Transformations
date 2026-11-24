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
CHECKS = {"isedrdeployed": ("isEDRDeployed", None), "iseppdeployed": ("isEPPDeployed", None),
          "offlinesensorcount": ("offlineSensorCount", None), "isolatedendpointcount": ("isolatedEndpointCount", None),
          "requiredcoveragepercentage": ("requiredCoveragePercentage", None)}


@pytest.mark.parametrize("body_in", FAIL_CLOSED)
@pytest.mark.parametrize("name", sorted(CHECKS))
def test_unreadable_is_not_evaluated(name, body_in):
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
    assert load("isedrdeployed")(short)["isEDRDeployed"] is None


def test_audit_log():
    t = load("isapiauditloggingenabled")
    assert t({"reply": {"total_count": 52, "result_count": 1, "data": [{"AUDIT_ID": 1}]}})["isApiAuditLoggingEnabled"] is True
    assert t({"reply": {"result_count": 1, "data": [{"AUDIT_ID": 1}]}})["isApiAuditLoggingEnabled"] is True
    assert t({"reply": {"total_count": 0, "result_count": 0, "data": []}})["isApiAuditLoggingEnabled"] is False
    for b in [{}, None, "{}", {"error": True}, {"reply": {}}]:
        assert t(b)["isApiAuditLoggingEnabled"] is None


def listed(statuses):
    return {"reply": {"total_count": len(statuses), "result_count": len(statuses),
                      "endpoints": [{"endpoint_id": "ep-" + str(i), "endpoint_status": s} for i, s in enumerate(statuses)]}}


def test_overnight_disconnected_endpoints_stay_covered():
    """A run at night: most endpoints DISCONNECTED (asleep), a few LOST. Coverage counts all but LOST."""
    t = load("requiredcoveragepercentage")
    night = {"enrolled": body(200), "connected": body(60), "lost": body(4), "offline": body(140), "isolated": body(0)}
    out = t(night)
    assert out["requiredCoveragePercentage"] == 98.0
    assert out["coveredEndpoints"] == 196 and out["lostEndpoints"] == 4
    assert out["coverageBasis"] == "notLost"
    assert "additionalInfo" not in out


def test_lost_from_disconnected_step():
    t = load("requiredcoveragepercentage")
    out = t({"enrolled": body(100), "connected": body(30), "offline": body(70), "disconnected": body(50)})
    assert out["requiredCoveragePercentage"] == 80.0
    assert out["lostEndpoints"] == 20


def test_lost_from_complete_offline_list():
    t = load("requiredcoveragepercentage")
    offline = listed(["DISCONNECTED"] * 7 + ["LOST"] * 3)
    out = t({"enrolled": body(20), "connected": body(10), "offline": offline})
    assert out["requiredCoveragePercentage"] == 85.0
    assert out["lostEndpoints"] == 3 and out["coveredEndpoints"] == 17


def test_no_offline_endpoints_is_full_coverage():
    t = load("requiredcoveragepercentage")
    out = t({"enrolled": body(12), "connected": body(12), "offline": body(0)})
    assert out["requiredCoveragePercentage"] == 100.0
    assert out["lostEndpoints"] == 0


def test_all_lost_flips_low():
    t = load("requiredcoveragepercentage")
    out = t({"enrolled": body(10), "connected": body(2), "offline": body(8), "lost": body(8)})
    assert out["requiredCoveragePercentage"] == 20.0


def test_lost_unreadable_falls_back_to_connected():
    """Offline list incomplete or statuses unreadable: the old connected/enrolled reading, labelled."""
    t = load("requiredcoveragepercentage")
    partial = {"reply": {"total_count": 10, "result_count": 2,
                         "endpoints": [{"endpoint_status": "LOST"}, {"endpoint_status": "DISCONNECTED"}]}}
    out = t({"enrolled": body(20), "connected": body(10), "offline": partial})
    assert out["requiredCoveragePercentage"] == 50.0
    assert out["coverageBasis"] == "connected" and "lostEndpoints" not in out
    unlabelled = listed([None, "LOST"])
    out = t({"enrolled": body(4), "connected": body(2), "offline": unlabelled})
    assert out["coverageBasis"] == "connected"


def test_inconsistent_lost_falls_back():
    t = load("requiredcoveragepercentage")
    out = t({"enrolled": body(10), "connected": body(8), "offline": body(2), "lost": body(5)})
    assert out["coverageBasis"] == "connected" and out["requiredCoveragePercentage"] == 80.0
