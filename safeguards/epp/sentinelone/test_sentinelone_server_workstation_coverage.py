"""SentinelOne requiredCoveragePercentage: the server / workstation split (additive).

machineType "server" is a server; "desktop" and "laptop" are workstations; anything else
("kubernetes node", "storage", "unknown", missing) is unclassified. "Protected" is the transform's own
covered test (not uninstalled, not decommissioned) over the same judged (non-stale) agents, so the
split agrees with the blended figure. A class with no agent is None, never 0; a partial or failed read
gives None for every split field. Synthetic agents only.
"""
import importlib.util
from datetime import datetime, timedelta
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "s1_split_cov", Path(__file__).with_name("requiredCoveragePercentage.py"))
COV = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COV)

NOW = datetime.utcnow()
SPLIT_KEYS = ("edrServerCoveragePercentage", "edrWorkstationCoveragePercentage", "edrTotalServerCount",
              "edrProtectedServerCount", "edrTotalWorkstationCount", "edrProtectedWorkstationCount",
              "edrUnclassifiedDeviceCount")
EXISTING_KEYS = ("requiredCoveragePercentage", "installedAgents", "activeAgents", "inactiveAgents",
                 "totalEnrolledAgents", "uninstalledAgents", "decommissionedAgents", "staleAgentCount")


def agent(i, machine_type="laptop", good=True, days_ago=0):
    record = {"id": str(i), "computerName": "host" + str(i), "isActive": True,
              "isUninstalled": not good, "isDecommissioned": False,
              "lastActiveDate": (NOW - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")}
    if machine_type is not None:
        record["machineType"] = machine_type
    return record


def ts(agents, total=None, cursor=None):
    pagination = {"totalItems": len(agents) if total is None else total, "nextCursor": cursor}
    raw = {"result": {"data": agents, "pagination": pagination,
                      "apiResponse": {"data": agents, "pagination": pagination}}}
    return {"data": raw, "validation": {"status": "skipped", "errors": [], "warnings": []}}


def run(payload):
    return COV.transform(payload)


def out(payload):
    return run(payload)["transformedResponse"]


def test_mixed_fleet_one_unprotected_server_with_blended_coverage_at_least_95():
    agents = [agent(i, "laptop") for i in range(60)] + [agent(100 + i, "desktop") for i in range(30)]
    agents += [agent(200 + i, "server") for i in range(9)] + [agent(300, "server", good=False)]
    result = out(ts(agents))
    assert result["requiredCoveragePercentage"] == 99.0
    assert (result["edrTotalServerCount"], result["edrProtectedServerCount"]) == (10, 9)
    assert result["edrServerCoveragePercentage"] == 90.0
    assert (result["edrTotalWorkstationCount"], result["edrProtectedWorkstationCount"]) == (90, 90)
    assert result["edrWorkstationCoveragePercentage"] == 100.0
    assert result["edrUnclassifiedDeviceCount"] == 0


def test_machine_type_is_case_insensitive():
    result = out(ts([agent(1, "Server"), agent(2, "DESKTOP"), agent(3, " Laptop ")]))
    assert result["edrTotalServerCount"] == 1
    assert result["edrTotalWorkstationCount"] == 2


def test_no_servers_means_server_coverage_is_none_not_zero():
    result = out(ts([agent(1, "laptop"), agent(2, "desktop", good=False)]))
    assert result["edrServerCoveragePercentage"] is None
    assert result["edrTotalServerCount"] == 0
    assert result["edrWorkstationCoveragePercentage"] == 50.0


def test_unclassifiable_agent_counts_in_neither_class():
    agents = [agent(1, "server"), agent(2, "laptop"), agent(3, "kubernetes node"),
              agent(4, "storage"), agent(5, "unknown"), agent(6, None)]
    result = out(ts(agents))
    assert result["edrUnclassifiedDeviceCount"] == 4
    assert result["edrTotalServerCount"] == 1
    assert result["edrTotalWorkstationCount"] == 1
    assert result["totalEnrolledAgents"] == 6


def test_stale_agents_are_left_out_of_the_split_as_they_are_of_the_blend():
    agents = [agent(1, "server"), agent(2, "laptop"), agent(3, "server", days_ago=40)]
    result = out(ts(agents))
    assert result["staleAgentCount"] == 1
    assert result["edrTotalServerCount"] == 1
    assert result["edrTotalServerCount"] + result["edrTotalWorkstationCount"] + result["edrUnclassifiedDeviceCount"] \
        == result["totalEnrolledAgents"]


def test_existing_fields_are_unchanged():
    agents = [agent(i, "laptop") for i in range(19)] + [agent(50, "server", good=False)]
    response = run(ts(agents))
    result = response["transformedResponse"]
    assert {k: result[k] for k in EXISTING_KEYS} == {
        "requiredCoveragePercentage": 95.0, "installedAgents": 19, "activeAgents": 19, "inactiveAgents": 0,
        "totalEnrolledAgents": 20, "uninstalledAgents": 1, "decommissionedAgents": 0, "staleAgentCount": 0}
    assert set(result) == set(EXISTING_KEYS) | set(SPLIT_KEYS)
    assert response["additionalInfo"]["dataCollection"]["status"] == "success"
    assert response["additionalInfo"]["transformation"]["inputSummary"] == {
        "totalEnrolledAgents": 20, "installedAgents": 19, "activeAgents": 19, "inactiveAgents": 0,
        "uninstalledAgents": 1, "decommissionedAgents": 0, "coveragePercentage": 95.0}


def test_partial_or_failed_read_gives_none_for_every_split_field():
    agents = [agent(1, "server"), agent(2, "laptop")]
    partial = ts(agents, total=5)
    more_pages = ts(agents, cursor="next-page-token")
    error = {"errors": [{"code": 4010010, "title": "Authentication Failed"}]}
    stale_fleet = ts([agent(1, "server", days_ago=40)])
    for payload in (partial, more_pages, error, ts([]), stale_fleet):
        response = run(payload)
        assert response["additionalInfo"]["dataCollection"]["status"] == "error"
        assert response["transformedResponse"]["requiredCoveragePercentage"] is None
        for key in SPLIT_KEYS:
            assert response["transformedResponse"][key] is None, key


def fleet(n_servers, bad_servers, n_workstations, bad_workstations):
    agents = [agent(i, "server", good=i >= bad_servers) for i in range(n_servers)]
    agents += [agent(100000 + i, "laptop", good=i >= bad_workstations) for i in range(n_workstations)]
    return ts(agents)


def test_edr_percentages_never_round_up_to_a_boundary():
    # 100 only when every agent in the class is protected; 94.9 stays below a 95 bar.
    for servers, bad, want in ((200, 1, 99.5), (2000, 1, 99.95), (20000, 1, 99.99), (200, 0, 100)):
        assert out(fleet(servers, bad, 0, 0))["edrServerCoveragePercentage"] == want
    assert out(fleet(0, 0, 1000, 51))["edrWorkstationCoveragePercentage"] == 94.9
    assert out(fleet(0, 0, 3, 1))["edrWorkstationCoveragePercentage"] == 66.66
    assert out(fleet(0, 0, 1000, 50))["edrWorkstationCoveragePercentage"] == 95
