"""SentinelOne Singularity sensor counts: 15-day window on the newest check-in, stale as its own number,
None on anything that is not a complete agent read."""
import importlib.util
import os

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
KEYS = ["staleSensorCount", "offlineSensorCount", "sensorOutOfDateCount"]


def load(name):
    spec = importlib.util.spec_from_file_location("s1_singularity_" + name, os.path.join(HERE, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def agent(i, active=True, up_to_date=True, uninstalled=False, last="2026-09-30T12:00:00.000000Z"):
    return {"id": str(i), "isActive": active, "isUpToDate": up_to_date, "isUninstalled": uninstalled,
            "isDecommissioned": False, "lastActiveDate": last}


def body(items, total=None, next_cursor=None, truncated=False):
    pagination = {"totalItems": len(items) if total is None else total, "nextCursor": next_cursor}
    if truncated:
        pagination["truncated"] = True
    return {"data": {"data": items, "pagination": pagination, "apiResponse": {"data": items, "pagination": pagination}},
            "validation": {"status": "skipped", "errors": [], "warnings": []}}


def out(key, payload):
    return load(key)(payload)["transformedResponse"]


GOOD = [agent(1), agent(2), agent(3, last="2026-09-20T08:00:00Z")]
MIXED = [
    agent(1),
    agent(2, active=False),                            # offline, inside the window
    agent(3, up_to_date=False, last="2026-09-16T13:00:00Z"),  # out of date, 14 days before newest
    agent(4, last="2026-09-01T00:00:00Z"),            # stale: 29 days before newest
    agent(5, last=None),                               # stale: no check-in at all
    agent(6, uninstalled=True, active=False, last="2020-01-01T00:00:00Z"),  # not installed: ignored
]


@pytest.mark.parametrize("key,good,mixed", [
    ("staleSensorCount", 0, 2),
    ("offlineSensorCount", 0, 1),
    ("sensorOutOfDateCount", 0, 1),
])
def test_counts_on_a_complete_read(key, good, mixed):
    assert out(key, body(GOOD))[key] == good
    result = out(key, body(MIXED))
    assert result[key] == mixed
    assert result["installedAgents"] == 5
    assert result["judgedAgents"] == 3
    assert result["staleSensorCount"] == 2
    assert result["windowDays"] == 15


def test_window_is_relative_to_newest_check_in_not_wall_clock():
    old_fleet = [agent(1, last="2019-05-01T00:00:00Z"), agent(2, last="2019-04-20T00:00:00Z", active=False)]
    assert out("staleSensorCount", body(old_fleet))["staleSensorCount"] == 0
    assert out("offlineSensorCount", body(old_fleet))["offlineSensorCount"] == 1


def test_all_stale_leaves_nothing_to_judge():
    fleet = [agent(1, last=None), agent(2, last="bad")]
    assert out("staleSensorCount", body(fleet))["staleSensorCount"] == 2
    assert out("offlineSensorCount", body(fleet))["offlineSensorCount"] is None
    assert out("sensorOutOfDateCount", body(fleet))["sensorOutOfDateCount"] is None


@pytest.mark.parametrize("key", KEYS)
@pytest.mark.parametrize("payload", [
    None, {}, [], "",
    {"errors": [{"code": 4010010, "title": "Authentication Failed"}]},
    {"data": {"foo": "bar"}},
    body([]),
    body([agent(1)], total=5),
    body([agent(1)], next_cursor="abc"),
    body([agent(1)], truncated=True),
    body([agent(1, uninstalled=True)]),
])
def test_no_evidence_or_partial_read_is_none(key, payload):
    assert out(key, payload)[key] is None
