"""Huntress Managed EDR transforms: real verdicts on complete reads, None on anything else."""
import importlib.util
import os

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name):
    spec = importlib.util.spec_from_file_location("huntress_medr_" + name, os.path.join(HERE, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def agent(i, last="2026-09-30T10:00:00Z"):
    return {"id": i, "hostname": "h" + str(i), "platform": "windows", "last_callback_at": last}


def report(i, status="sent", severity="high"):
    return {"id": i, "status": status, "severity": severity}


def body(list_key, items, next_token=None, truncated=False):
    pagination = {"next_page_token": next_token, "next_page_url": None}
    if truncated:
        pagination["truncated"] = True
    inner = {list_key: items, "pagination": pagination}
    return {"data": {"apiResponse": inner}, "validation": {"status": "skipped", "errors": [], "warnings": []}}


def value(key, payload):
    return load(key)(payload)["transformedResponse"][key]


FRESH = [agent(1), agent(2), agent(3), agent(4)]
MIXED = [agent(1), agent(2, last="2026-09-20T10:00:00Z"), agent(3, last="2026-08-01T00:00:00Z"), agent(4, last=None)]

AGENT_CASES = [
    ("isEDRAgentActive", True, True),
    ("staleAgentOfflineCount", 0, 2),
    ("assetInventoryCoveragePercentage", 100.0, 50.0),
]


@pytest.mark.parametrize("key,fresh,mixed", AGENT_CASES)
def test_agent_keys_measure_a_complete_read(key, fresh, mixed):
    assert value(key, body("agents", FRESH)) == fresh
    assert value(key, body("agents", MIXED)) == mixed


def test_window_is_relative_to_newest_callback_not_wall_clock():
    old = [agent(1, last="2020-01-01T00:00:00Z"), agent(2, last="2020-01-10T00:00:00Z")]
    assert value("staleAgentOfflineCount", body("agents", old)) == 0
    assert value("isEDRAgentActive", body("agents", old)) is True


def test_empty_fleet():
    assert value("isEDRAgentActive", body("agents", [])) is False
    assert value("staleAgentOfflineCount", body("agents", [])) == 0
    assert value("assetInventoryCoveragePercentage", body("agents", [])) is None


def test_never_called_back_fleet_is_not_active():
    assert value("isEDRAgentActive", body("agents", [agent(1, last=None)])) is False


def test_open_incident_count():
    assert value("openMDRCasesCount", body("incident_reports", [report(1), report(2, severity="critical")])) == 2
    assert value("openMDRCasesCount", body("incident_reports", [])) == 0
    assert value("openMDRCasesCount", body("incident_reports", [report(1, status="closed")])) is None


def test_account_status():
    ok = {"data": {"account": {"id": 7, "status": "enabled"}}, "validation": {}}
    off = {"data": {"account": {"id": 7, "status": "disabled"}}, "validation": {}}
    assert value("isMDREnabled", ok) is True
    assert value("isMDREnabled", off) is False


NO_EVIDENCE = [
    None, {}, [], "",
    {"errors": ["Unauthorized"]},
    {"error": "invalid credentials", "status_code": 401},
    {"status": 403, "message": "Forbidden"},
    {"data": {"unrelated": 1}, "validation": {"status": "skipped", "errors": [], "warnings": []}},
]
ALL_KEYS = [c[0] for c in AGENT_CASES] + ["openMDRCasesCount", "isMDREnabled"]


@pytest.mark.parametrize("key", ALL_KEYS)
@pytest.mark.parametrize("payload", NO_EVIDENCE)
def test_no_evidence_is_not_measured(key, payload):
    out = load(key)(payload)
    assert out["transformedResponse"][key] is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"


@pytest.mark.parametrize("key", [c[0] for c in AGENT_CASES] + ["openMDRCasesCount"])
def test_partial_read_is_not_scored(key):
    list_key, items = ("incident_reports", [report(1)]) if key == "openMDRCasesCount" else ("agents", FRESH)
    assert value(key, body(list_key, items, next_token="abc")) is None
    assert value(key, body(list_key, items, truncated=True)) is None
