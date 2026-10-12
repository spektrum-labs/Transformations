"""Huntress Managed EDR transforms: real verdicts on complete reads, None on anything else."""
import importlib.util
import os
from datetime import datetime, timedelta

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name):
    spec = importlib.util.spec_from_file_location("huntress_medr_" + name, os.path.join(HERE, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def ago(days):
    """A last_callback_at timestamp this many days before now, so the tests hold on any date."""
    return (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def agent(i, last=None, days=1):
    last = last if last is not None else ago(days)
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
MIXED = [agent(1), agent(2, days=10), agent(3, days=60), {"id": 4, "hostname": "h4", "last_callback_at": None}]

AGENT_CASES = [
    ("isEDRAgentActive", True, True),
    ("staleAgentOfflineCount", 0, 2),
    ("assetInventoryCoveragePercentage", 100.0, 50.0),
]


@pytest.mark.parametrize("key,fresh,mixed", AGENT_CASES)
def test_agent_keys_measure_a_complete_read(key, fresh, mixed):
    assert value(key, body("agents", FRESH)) == fresh
    assert value(key, body("agents", MIXED)) == mixed


def test_newest_callback_wins_whatever_the_order():
    ages = [200, 3, 90]
    for order in ([0, 1, 2], [1, 0, 2], [2, 0, 1]):
        agents = [agent(i + 1, days=ages[j]) for i, j in enumerate(order)]
        assert value("isEDRAgentActive", body("agents", agents)) is True


def test_one_recent_agent_is_enough_among_dark_ones():
    agents = [agent(1, days=400), agent(2, days=90), agent(3, days=2), agent(4, days=250)]
    assert value("isEDRAgentActive", body("agents", agents)) is True


def test_dark_fleet_is_not_active_even_though_its_newest_agent_is_the_newest():
    # Every agent has been silent for longer than the limit: judged against now, none is active.
    old = [agent(1, days=200), agent(2, days=190)]
    assert value("isEDRAgentActive", body("agents", old)) is False
    assert value("staleAgentOfflineCount", body("agents", old)) == 2
    assert value("assetInventoryCoveragePercentage", body("agents", old)) == 0.0
    out = load("isEDRAgentActive")(body("agents", old))
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"
    assert out["transformedResponse"]["activeAgents"] == 0


def test_threshold_is_fifteen_days_from_now():
    assert value("isEDRAgentActive", body("agents", [agent(1, days=14)])) is True
    assert value("isEDRAgentActive", body("agents", [agent(1, days=16)])) is False


def test_empty_fleet():
    # Nothing to judge: not measured, never a graded False or True.
    assert value("isEDRAgentActive", body("agents", [])) is None
    assert load("isEDRAgentActive")(body("agents", []))["additionalInfo"]["dataCollection"]["status"] == "error"
    assert value("staleAgentOfflineCount", body("agents", [])) == 0
    assert value("assetInventoryCoveragePercentage", body("agents", [])) is None


def test_error_body_is_not_measured():
    for payload in ({"data": {"apiResponse": {"errors": ["Unauthorized"]}}, "validation": {}},
                    {"data": {"apiResponse": {"error": "invalid credentials", "status_code": 401}}, "validation": {}},
                    {"data": {"apiResponse": {"status": 500, "message": "boom"}}, "validation": {}}):
        out = load("isEDRAgentActive")(payload)
        assert out["transformedResponse"]["isEDRAgentActive"] is None
        assert out["additionalInfo"]["dataCollection"]["status"] == "error"


def test_never_called_back_fleet_is_not_active():
    assert value("isEDRAgentActive", body("agents", [{"id": 1, "last_callback_at": None}, {"id": 2, "last_callback_at": None}])) is False


def test_missing_data_is_never_active():
    # Unparseable and absent timestamps are not a callback; they can never make the check pass.
    assert value("isEDRAgentActive", body("agents", [{"id": 1}, agent(2, last="not a date")])) is False


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
