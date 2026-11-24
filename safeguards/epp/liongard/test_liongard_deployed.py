"""Liongard isAgentDeployed / isEPPDeployed: deployed regardless of momentary online state, judged within
the 15-day window on the newest last-seen time; unreadable bodies are not evaluated. Synthetic data only."""
import importlib.util
import pathlib
from datetime import datetime, timedelta, timezone

import pytest

HERE = pathlib.Path(__file__).resolve().parent
NOW = datetime.now(timezone.utc)


def load(name):
    spec = importlib.util.spec_from_file_location("liongard_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def iso(days_ago):
    return (NOW - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def agent(i, status="Online", days_ago=0):
    return {"ID": 1000 + i, "Name": "agent-" + str(i), "Status": status, "LastHeartbeat": iso(days_ago)}


def device(i, status="Online", days_ago=0, managed=None, lifecycle=None):
    d = {"id": "dev-" + str(i), "status": status, "lastSeen": iso(days_ago)}
    if managed is not None:
        d["managed"] = managed
    if lifecycle is not None:
        d["lifecycleStatus"] = lifecycle
    return d


def run(name, body):
    out = load(name)(body)
    return out["transformedResponse"], out["additionalInfo"]


def test_overnight_offline_agents_are_deployed():
    agents = [agent(i, status="Offline", days_ago=1) for i in range(8)] + [agent(8), agent(9)]
    result, info = run("isagentdeployed", {"Data": agents})
    assert result["isAgentDeployed"] is True
    assert result["deployedAgents"] == 10
    assert info["dataCollection"]["status"] == "success"


def test_removed_agents_fail():
    agents = [agent(1), agent(2, status="Uninstalled"), agent(3, status="Disabled"), agent(4, status="Offline")]
    result, _ = run("isagentdeployed", {"data": agents})
    assert result["isAgentDeployed"] is False
    assert result["deployedPercentage"] == 50.0


def test_stale_agents_left_out():
    agents = [agent(1, status="Uninstalled", days_ago=40), agent(2), agent(3, status="Offline", days_ago=3)]
    result, _ = run("isagentdeployed", {"data": agents})
    assert result["isAgentDeployed"] is True
    assert result["staleAgentCount"] == 1 and result["totalAgents"] == 2


def test_agents_without_last_seen_are_all_judged():
    agents = [{"Name": "a", "Status": "Offline"}, {"Name": "b", "Status": "Online"}]
    out = load("isagentdeployed")({"data": agents})
    assert out["transformedResponse"]["isAgentDeployed"] is True
    assert any("no last-seen" in f for f in out["additionalInfo"]["evaluation"]["additionalFindings"])


def test_dark_agent_fleet_is_not_evaluated():
    result, info = run("isagentdeployed", {"data": [agent(1, days_ago=30), agent(2, days_ago=40)]})
    assert result["isAgentDeployed"] is None
    assert info["dataCollection"]["status"] == "error"


def test_empty_agent_list_is_false():
    result, info = run("isagentdeployed", {"data": []})
    assert result["isAgentDeployed"] is False
    assert info["dataCollection"]["status"] == "success"


def test_offline_monitored_devices_are_deployed():
    devices = [device(i, status="Offline", days_ago=2) for i in range(9)] + [device(9)]
    result, _ = run("iseppdeployed", {"response": {"data": devices}})
    assert result["isEPPDeployed"] is True
    assert result["deployedCount"] == 10 and result["coveragePercentage"] == 100.0


def test_unmonitored_or_retired_devices_fail():
    devices = [device(1), device(2, status="", managed=False), device(3, status="Offline", lifecycle="retired"),
               device(4, status="Decommissioned"), device(5, status="", managed=True)]
    result, _ = run("iseppdeployed", {"data": devices})
    assert result["isEPPDeployed"] is False
    assert result["deployedCount"] == 2


def test_stale_devices_left_out():
    devices = [device(1), device(2, status="", managed=False, days_ago=25)]
    result, _ = run("iseppdeployed", {"data": devices})
    assert result["isEPPDeployed"] is True
    assert result["staleDeviceCount"] == 1


@pytest.mark.parametrize("name,key", [("isagentdeployed", "isAgentDeployed"), ("iseppdeployed", "isEPPDeployed")])
@pytest.mark.parametrize("body", [None, {}, "", "{}", "not json", {"error": "Unauthorized", "statusCode": 401},
                                  {"hello": "world"}, {"response": {"errors": ["forbidden"]}}])
def test_unreadable_is_not_evaluated(name, key, body):
    result, info = run(name, body)
    assert result[key] is None
    assert info["dataCollection"]["status"] == "error" and info["dataCollection"]["errors"]
