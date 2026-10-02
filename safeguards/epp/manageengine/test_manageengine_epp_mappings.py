"""ManageEngine Endpoint Central anti-malware checks: isEPPEnabled, isEPPConfigured, requiredCoveragePercentage.

Synthetic bodies in ManageEngine's documented shapes only (GET /edr/api/view/devices and GET /api/1.4/som/computers,
API reference samples); no customer data. Each check answers only on a complete measurement and is not evaluated
(value None, dataCollection "error") on an empty, failed, partial or truncated read.
"""
import copy
import importlib.util
import json
import pathlib

import pytest

HERE = pathlib.Path(__file__).resolve().parent
DAY_MS = 24 * 60 * 60 * 1000
NEWEST = 1790000000000


def load(name):
    spec = importlib.util.spec_from_file_location("me_epp_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


ENABLED = load("iseppenabled")
CONFIGURED = load("iseppconfigured")
COVERAGE = load("requiredcoveragepercentage")


def device(rid, status="1", days_ago=0, **over):
    row = {"resource_id": str(rid), "resource_name_transform": "HOST-" + str(rid), "component_status_transform": status,
           "agent_last_contact_time": str(NEWEST - days_ago * DAY_MS), "error_code": None, "is_suspended": "false",
           "isolation_status": None, "def_file_version": "260101120000", "remarks_transform": "Protection Enabled"}
    row.update(over)
    return row


def edr(rows, total=None, next_link="null"):
    return {"status": "success", "totalRecords": str(len(rows) if total is None else total), "totalPages": 1,
            "metadata": {"limit": 1000, "page": 1}, "Links": {"next": next_link, "prev": None},
            "messageResponse": rows}


def computer(rid, installed=True, days_ago=0):
    return {"resource_id": rid, "resource_name": "HOST-" + str(rid), "installation_status": 22 if installed else 21,
            "managed_status": 61, "agent_last_contact_time": NEWEST - days_ago * DAY_MS, "os_platform": 1}


def som(rows, total=None):
    return {"message_type": "computers", "status": "success", "message_version": "1.4",
            "message_response": {"total": len(rows) if total is None else total, "limit": 1000, "page": 1,
                                 "computers": rows}}


def run(fn, body, key):
    out = fn(copy.deepcopy(body))
    return out["transformedResponse"].get(key), out["additionalInfo"]["dataCollection"]["status"], out


def healthy_fleet(n=10):
    return edr([device(i) for i in range(1, n + 1)])


# ---------------------------------------------------------------- isEPPEnabled

def test_enabled_true_when_every_judged_device_runs_protection():
    value, status, _ = run(ENABLED, healthy_fleet(), "isEPPEnabled")
    assert (value, status) == (True, "success")


def test_quarantined_device_still_runs_protection():
    rows = [device(1), device(2, status="11")]
    assert run(ENABLED, edr(rows), "isEPPEnabled")[:2] == (True, "success")


@pytest.mark.parametrize("status", ["0", "8"])
def test_enabled_false_when_a_device_has_protection_installed_but_not_running(status):
    rows = [device(1), device(2), device(3, status=status)]
    value, state, out = run(ENABLED, edr(rows), "isEPPEnabled")
    assert (value, state) == (False, "success")
    assert out["transformedResponse"]["protectionNotRunningCount"] == 1


def test_stale_device_is_left_out_and_counted():
    rows = [device(1), device(2, status="8", days_ago=20)]
    value, state, out = run(ENABLED, edr(rows), "isEPPEnabled")
    assert (value, state) == (True, "success")
    assert out["transformedResponse"]["staleDeviceCount"] == 1


def test_enabled_reads_the_wrapped_and_merged_shapes():
    body = {"data": {"edrDevices": healthy_fleet()}, "validation": {"status": "skipped", "errors": [], "warnings": []}}
    assert run(ENABLED, body, "isEPPEnabled")[:2] == (True, "success")
    assert run(ENABLED, json.dumps({"apiResponse": healthy_fleet()}), "isEPPEnabled")[:2] == (True, "success")


# ------------------------------------------------------------- isEPPConfigured

def test_configured_is_a_floored_whole_number_percentage():
    rows = [device(i) for i in range(1, 9)] + [device(9, status="8"), device(10, error_code="EDR104")]
    value, state, out = run(CONFIGURED, edr(rows), "isEPPConfigured")
    assert (value, state) == (80, "success") and type(value) is int
    rows = [device(i) for i in range(1, 9)] + [device(9, def_file_version="")]
    assert run(CONFIGURED, edr(rows), "isEPPConfigured")[:2] == (88, "success")


@pytest.mark.parametrize("fault", [{"component_status_transform": "0"}, {"component_status_transform": "8"},
                                   {"component_status_transform": "11"}, {"error_code": "EDR104"},
                                   {"is_suspended": "true"}, {"isolation_status": "isolated"},
                                   {"def_file_version": None}])
def test_each_documented_fault_moves_the_number(fault):
    rows = [device(i) for i in range(1, 10)] + [device(10, **fault)]
    assert run(CONFIGURED, edr(rows), "isEPPConfigured")[:2] == (90, "success")


def test_healthy_fleet_reads_100():
    assert run(CONFIGURED, healthy_fleet(), "isEPPConfigured")[:2] == (100, "success")


# -------------------------------------------------- requiredCoveragePercentage

def coverage_body(computers, devices):
    return {"computers": som(computers), "edrDevices": edr(devices)}


def test_coverage_counts_computers_with_protection_running():
    computers = [computer(i) for i in range(1, 11)]
    devices = [device(i) for i in range(1, 8)] + [device(8, status="0")]
    value, state, out = run(COVERAGE, coverage_body(computers, devices), "requiredCoveragePercentage")
    assert (value, state) == (70, "success") and type(value) is int
    assert out["transformedResponse"]["computersWithoutProtection"] == 2
    assert out["transformedResponse"]["computersProtectionNotRunning"] == 1


def test_management_agent_alone_is_not_coverage():
    computers = [computer(i) for i in range(1, 5)]
    devices = [device(1), device(2)]
    assert run(COVERAGE, coverage_body(computers, devices), "requiredCoveragePercentage")[:2] == (50, "success")


def test_full_coverage_reads_100_and_window_and_install_rules_apply():
    computers = [computer(i) for i in range(1, 5)] + [computer(5, days_ago=40), computer(6, installed=False)]
    devices = [device(i) for i in range(1, 5)]
    value, state, out = run(COVERAGE, coverage_body(computers, devices), "requiredCoveragePercentage")
    assert (value, state) == (100, "success")
    assert out["transformedResponse"]["staleComputerCount"] == 1
    assert out["transformedResponse"]["agentNotInstalledCount"] == 1


# ------------------------------------------------- fail closed, every transform

ERROR_BODIES = [
    {},
    None,
    "{}",
    {"error": True, "errorType": "authentication", "statusCode": 401, "message": "Authentication Failed"},
    {"errorCode": "EDRCOMMON001", "errorMessage": "Exception while retrieving EDR device list"},
    {"errorCode": "IAM0019", "url": "/edr/api/view/devices", "errorMsg": "called too many times"},
    {"error_description": "User is not authorized to access this API", "message_type": "edr", "error_code": "1010",
     "message_version": "1.4", "status": "error"},
    {"status": "success", "messageResponse": None},
]

EDR_PARTIAL = [
    edr([]),
    edr([device(1), device(2)], total=40),
    edr([device(1), device(2)], next_link="/edr/api/view/devices?page=2&pageLimit=2"),
    {"status": "success", "totalRecords": "4", "totalPages": 2, "metadata": {"limit": 2, "page": 1},
     "Links": {"next": "null"}, "messageResponse": [device(1), device(2)]},
    edr([device(1, agent_last_contact_time=None), device(2, agent_last_contact_time="-1")]),
    edr([device(1), device(2, status="5")]),
    edr([device(1), device(2, component_status_transform=None)]),
]


@pytest.mark.parametrize("fn,key", [(ENABLED, "isEPPEnabled"), (CONFIGURED, "isEPPConfigured")])
@pytest.mark.parametrize("body", ERROR_BODIES + EDR_PARTIAL)
def test_device_list_checks_are_not_evaluated_without_a_complete_list(fn, key, body):
    value, state, out = run(fn, body, key)
    assert value is None and state == "error"
    assert key in out["transformedResponse"]


COVERAGE_PARTIAL = [
    {"computers": som([computer(1)])},
    {"edrDevices": edr([device(1)])},
    {"computers": som([computer(1), computer(2)], total=600), "edrDevices": edr([device(1), device(2)])},
    {"computers": {"message_type": "computers", "status": "success",
                   "message_response": {"computers": [computer(1)]}}, "edrDevices": edr([device(1)])},
    {"computers": som([computer(1)]), "edrDevices": edr([])},
    {"computers": som([computer(1)]), "edrDevices": edr([device(1)], total=30)},
    {"computers": som([computer(1, installed=False)]), "edrDevices": edr([device(1)])},
    {"computers": som([computer(1)]), "edrDevices": edr([device(1, status="5")])},
    {"computers": {"error_description": "User is not authorized to access this API", "error_code": "1010",
                   "status": "error"}, "edrDevices": edr([device(1)])},
    {"computers": som([computer(1)]),
     "edrDevices": {"error": True, "errorType": "authentication", "statusCode": 401}},
]


@pytest.mark.parametrize("body", ERROR_BODIES + COVERAGE_PARTIAL)
def test_coverage_is_not_evaluated_without_both_complete_reads(body):
    value, state, out = run(COVERAGE, body, "requiredCoveragePercentage")
    assert value is None and state == "error"
