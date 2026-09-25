"""KnowBe4 (Email Security) checks on bodies shaped like the Reporting API spec (developer.knowbe4.com
/elvis-swagger.yml). No customer body has been seen: each check has a pass, a flip that must not pass,
and the fail-closed inputs."""
import datetime
import importlib.util
import pathlib

import pytest

HERE = pathlib.Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location("kb4_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def ago(days):
    t = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)
    return t.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def pst(days, status="Closed", ppp=0.12, pid=1):
    return {"pst_id": pid, "status": status, "started_at": ago(days), "phish_prone_percentage": ppp, "delivered_count": 40}


FAIL_CLOSED = [{}, None, "{}", "", {"error": True, "statusCode": 401, "message": "Unauthorized"}, {"hello": "world"}]


@pytest.mark.parametrize("body", FAIL_CLOSED)
def test_fail_closed(body):
    assert load("averageuserriskscore")(body)["averageUserRiskScore"] is None
    assert load("isattacksimulationtrainingenabled")(body)["isAttackSimulationTrainingEnabled"] is False
    assert load("phishingsimulationclickrate")(body)["phishingSimulationClickRate"] is None
    assert load("trainingcompletionrate")(body)["trainingCompletionRate"] is None


def test_average_user_risk_score():
    users = [{"id": 1, "status": "active", "current_risk_score": 40.0}, {"id": 2, "status": "active", "current_risk_score": 20.5},
             {"id": 3, "status": "active", "current_risk_score": None}]
    assert load("averageuserriskscore")({"apiResponse": users})["averageUserRiskScore"] == 30.25
    assert load("averageuserriskscore")([{"id": 1, "current_risk_score": None}])["averageUserRiskScore"] is None
    assert load("averageuserriskscore")([])["averageUserRiskScore"] is None


def test_simulation_enabled_needs_a_recent_test():
    t = load("isattacksimulationtrainingenabled")
    assert t([pst(400), pst(30, status="Active")])["isAttackSimulationTrainingEnabled"] is True
    assert t([pst(400), pst(120)])["isAttackSimulationTrainingEnabled"] is False
    assert t([])["isAttackSimulationTrainingEnabled"] is False


def test_click_rate_is_latest_closed_test():
    t = load("phishingsimulationclickrate")
    assert t([pst(200, ppp=0.5, pid=1), pst(20, ppp=0.034, pid=2), pst(5, status="Active", ppp=0.9, pid=3)])["phishingSimulationClickRate"] == 3.4
    assert t([pst(5, status="Active")])["phishingSimulationClickRate"] is None
    assert t([pst(5, ppp=14.2)])["phishingSimulationClickRate"] is None


def test_training_completion_rate():
    t = load("trainingcompletionrate")
    rows = [{"status": s} for s in ["Passed", "Completed", "In Progress", "Past Due"]]
    assert t(rows)["trainingCompletionRate"] == 50.0
    assert t(rows + [{"status": "Mystery"}])["trainingCompletionRate"] is None
    assert t([])["trainingCompletionRate"] is None
