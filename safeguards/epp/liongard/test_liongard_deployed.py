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


# ---- follow-up review of #1442: being listed is not evidence of deployment

@pytest.mark.parametrize("agents", [[{}], [{"ID": 1, "Name": "agent-1"}], [{"Name": "a", "Status": None}],
                                    [{"Name": "a", "Status": ""}]])
def test_agents_without_readable_status_are_not_evaluated(agents):
    # Reviewer's case: [{}] and an agent with no status read True after #1442 (False before).
    result, info = run("isagentdeployed", {"data": agents})
    assert result["isAgentDeployed"] is None
    assert info["dataCollection"]["status"] == "error"


@pytest.mark.parametrize("status", ["Failed", "Pending", "Error", "Unknown", "Inactive"])
def test_agent_with_a_status_that_shows_no_install_is_not_deployed(status):
    result, info = run("isagentdeployed", {"data": [agent(1, status=status)]})
    assert result["isAgentDeployed"] is False
    assert info["dataCollection"]["status"] == "success"


def test_agents_without_status_count_against_and_are_reported():
    agents = [agent(1), agent(2, status="Offline"), {"Name": "c"}, {"Name": "d", "LastHeartbeat": iso(0)}]
    out = load("isagentdeployed")({"data": agents})
    result = out["transformedResponse"]
    assert result["isAgentDeployed"] is False
    assert result["deployedAgents"] == 2 and result["unreadAgentCount"] == 2
    assert any("unreadAgentCount" in f for f in out["additionalInfo"]["evaluation"]["additionalFindings"])


def test_agent_installed_flag_is_positive_evidence():
    result, _ = run("isagentdeployed", {"data": [{"Name": "a", "Installed": True}, {"Name": "b", "isInstalled": "true"}]})
    assert result["isAgentDeployed"] is True
    result, _ = run("isagentdeployed", {"data": [{"Name": "a", "Installed": False, "Status": "Online"}]})
    assert result["isAgentDeployed"] is False


@pytest.mark.parametrize("devices", [[{}], [{"id": "dev-1"}], [{"id": "dev-1", "status": None, "lastSeen": iso(0)}]])
def test_devices_without_readable_status_are_not_evaluated(devices):
    result, info = run("iseppdeployed", {"data": devices})
    assert result["isEPPDeployed"] is None
    assert info["dataCollection"]["status"] == "error"


def test_devices_without_status_count_against_and_are_reported():
    devices = [device(1), device(2), device(3), device(4), {"id": "dev-5"}]
    out = load("iseppdeployed")({"data": devices})
    result = out["transformedResponse"]
    assert result["isEPPDeployed"] is True and result["coveragePercentage"] == 80.0
    assert result["unreadDeviceCount"] == 1
    failed = load("iseppdeployed")({"data": [device(1, status="Failed")]})["transformedResponse"]
    assert failed["isEPPDeployed"] is False
