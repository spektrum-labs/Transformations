"""CrowdStrike requiredCoveragePercentage: the server / workstation split (additive).

The transform also reports coverage per class so a later rule can ask for every server and most
workstations. A host is a server when product_type_desc is "Server" or "Domain Controller" (or, with
no product_type_desc, product_type 3 or 2), a workstation when it is "Workstation" (or product_type
1), and unclassified otherwise. "Protected" is exactly the transform's own active-sensor test, so the
split agrees with the blended figure. A class with no host is None, never 0; a truncated or failed
read gives None for every split field. Synthetic hosts only.
"""
import copy
import importlib.util
import json
import pathlib
from datetime import datetime, timedelta

HERE = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("cs_split_cov", HERE / "requiredCoveragePercentage.py")
COV = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COV)

RECENT = (datetime.utcnow() - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
SPLIT_KEYS = ("edrServerCoveragePercentage", "edrWorkstationCoveragePercentage", "edrTotalServerCount",
              "edrProtectedServerCount", "edrTotalWorkstationCount", "edrProtectedWorkstationCount",
              "edrUnclassifiedDeviceCount")
EXISTING_KEYS = ("requiredCoveragePercentage", "activeDevices", "totalDevices", "notReportingDevices",
                 "containedDevices", "activeWindowDays")
DEVICES = json.loads((HERE / "fixtures" / "xdr_devices_unpaged_real_2026-09-25.json").read_text())


def host(n, desc=None, ptype=None, good=True):
    record = {"device_id": "synthetic-%04d" % n, "status": "normal", "agent_version": "7.40.1",
              "last_seen": RECENT, "reduced_functionality_mode": "no"}
    if not good:
        record["agent_version"] = ""
    if desc is not None:
        record["product_type_desc"] = desc
    if ptype is not None:
        record["product_type"] = ptype
    return record


def body(hosts):
    return {"meta": {"pagination": {"total": len(hosts)}}, "resources": hosts}


def run(payload):
    return COV.transform(payload)


def out(payload):
    return run(payload)["transformedResponse"]


def test_mixed_fleet_one_unprotected_server_with_blended_coverage_at_least_95():
    hosts = [host(i, "Workstation") for i in range(90)]
    hosts += [host(100 + i, "Server") for i in range(8)]
    hosts += [host(200, "Domain Controller"), host(201, "Server", good=False)]
    result = out(body(hosts))
    assert result["requiredCoveragePercentage"] == 99.0
    assert result["edrTotalServerCount"] == 10
    assert result["edrProtectedServerCount"] == 9
    assert result["edrServerCoveragePercentage"] == 90.0
    assert result["edrTotalWorkstationCount"] == 90
    assert result["edrProtectedWorkstationCount"] == 90
    assert result["edrWorkstationCoveragePercentage"] == 100.0
    assert result["edrUnclassifiedDeviceCount"] == 0


def test_product_type_number_classifies_when_the_description_is_absent():
    hosts = [host(1, ptype="1"), host(2, ptype=1), host(3, ptype="3"), host(4, ptype="2", good=False)]
    result = out(body(hosts))
    assert (result["edrTotalWorkstationCount"], result["edrProtectedWorkstationCount"]) == (2, 2)
    assert (result["edrTotalServerCount"], result["edrProtectedServerCount"]) == (2, 1)
    assert result["edrServerCoveragePercentage"] == 50.0
    assert result["edrUnclassifiedDeviceCount"] == 0


def test_no_servers_means_server_coverage_is_none_not_zero():
    result = out(body([host(i, "Workstation") for i in range(3)]))
    assert result["edrServerCoveragePercentage"] is None
    assert result["edrTotalServerCount"] == 0
    assert result["edrWorkstationCoveragePercentage"] == 100.0
    no_workstations = out(body([host(1, "Server")]))
    assert no_workstations["edrWorkstationCoveragePercentage"] is None
    assert no_workstations["edrServerCoveragePercentage"] == 100.0


def test_unclassifiable_device_counts_in_neither_class():
    hosts = [host(1, "Workstation"), host(2, "Server"), host(3, "Mobile"), host(4), host(5, ptype="9")]
    result = out(body(hosts))
    assert result["edrUnclassifiedDeviceCount"] == 3
    assert result["edrTotalServerCount"] == 1
    assert result["edrTotalWorkstationCount"] == 1
    assert result["totalDevices"] == 5


def test_existing_fields_are_unchanged():
    hosts = [host(i, "Workstation") for i in range(19)] + [host(50, "Server", good=False)]
    response = run(body(hosts))
    result = response["transformedResponse"]
    assert {k: result[k] for k in EXISTING_KEYS} == {
        "requiredCoveragePercentage": 95.0, "activeDevices": 19, "totalDevices": 20,
        "notReportingDevices": 0, "containedDevices": 0, "activeWindowDays": 45}
    assert set(result) == set(EXISTING_KEYS) | set(SPLIT_KEYS)
    assert response["additionalInfo"]["dataCollection"]["status"] == "success"
    # The split adds no reason text: the evaluation section reads exactly as before.
    assert len(response["additionalInfo"]["evaluation"]["passReasons"]) == 1
    assert len(response["additionalInfo"]["evaluation"]["failReasons"]) == 1


def test_existing_fixture_outputs_are_unchanged():
    # The capture is replayed 60 days older than it was taken so that, whatever today's date, every host
    # is beyond the window and the fixture reads as a dark fleet, as it did when this test was written.
    aged = copy.deepcopy(DEVICES)
    for record in aged["resources"]:
        when = datetime.fromisoformat(record["last_seen"][:19]) - timedelta(days=60)
        record["last_seen"] = when.strftime("%Y-%m-%dT%H:%M:%SZ")
    response = run(aged)
    result = response["transformedResponse"]
    assert {k: result[k] for k in EXISTING_KEYS} == {
        "requiredCoveragePercentage": 0, "activeDevices": 0, "totalDevices": 100,
        "notReportingDevices": 100, "containedDevices": 0, "activeWindowDays": 45}
    assert response["additionalInfo"]["dataCollection"]["status"] == "error"


def test_truncated_or_failed_read_gives_none_for_every_split_field():
    hosts = [host(1, "Server"), host(2, "Workstation")]
    truncated = {"meta": {"pagination": {"total": 5}}, "resources": hosts}
    error = {"error": True, "message": "HTTP 403: Forbidden", "resources": hosts}
    for payload in (truncated, error, copy.deepcopy(DEVICES)):
        response = run(payload)
        assert response["additionalInfo"]["dataCollection"]["status"] == "error"
        for key in SPLIT_KEYS:
            assert response["transformedResponse"][key] is None, key


def test_empty_device_list_gives_none_for_every_edr_field():
    result = out(body([]))
    assert result["requiredCoveragePercentage"] == 0
    # An empty fleet with no error measures nothing: every edr* field is None, as in SentinelOne and Defender.
    for key in SPLIT_KEYS:
        assert result[key] is None, key


def fleet(n_servers, bad_servers, n_workstations, bad_workstations):
    hosts = [host(i, "Server", good=i >= bad_servers) for i in range(n_servers)]
    hosts += [host(100000 + i, "Workstation", good=i >= bad_workstations) for i in range(n_workstations)]
    return body(hosts)


def test_edr_percentages_never_round_up_to_a_boundary():
    # 100 only when every device in the class is protected; 94.9 stays below a 95 bar.
    for servers, bad, want in ((200, 1, 99.5), (2000, 1, 99.95), (20000, 1, 99.99), (200, 0, 100)):
        assert out(fleet(servers, bad, 0, 0))["edrServerCoveragePercentage"] == want
    assert out(fleet(0, 0, 1000, 51))["edrWorkstationCoveragePercentage"] == 94.9
    assert out(fleet(0, 0, 3, 1))["edrWorkstationCoveragePercentage"] == 66.66
    assert out(fleet(0, 0, 1000, 50))["edrWorkstationCoveragePercentage"] == 95
