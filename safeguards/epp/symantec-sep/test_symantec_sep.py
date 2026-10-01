"""Symantec Endpoint Protection (SEPM /computers) transforms: real verdicts on complete reads, None otherwise."""
import importlib.util
import os

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
DAY = 86400000
NEWEST = 1727700000000


def load(name):
    spec = importlib.util.spec_from_file_location("sep_" + name, os.path.join(HERE, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def client(i, age_days=0, av=1, infected=0, last="set"):
    c = {"computerName": "pc" + str(i), "onlineStatus": 1, "avEngineOnOff": av, "infected": infected,
         "lastUpdateTime": NEWEST - age_days * DAY}
    if last is None:
        c["lastUpdateTime"] = None
    return c


def body(items, total=None):
    inner = {"content": items, "totalElements": len(items) if total is None else total, "lastPage": True}
    return {"data": {"apiResponse": inner}, "validation": {"status": "skipped", "errors": [], "warnings": []}}


def value(key, payload):
    return load(key)(payload)["transformedResponse"][key]


GOOD = [client(1), client(2), client(3), client(4)]
MIXED = [client(1), client(2, av=0, infected=1), client(3, age_days=40), client(4, last=None)]

CASES = [
    ("isEPPDeployed", True, True),
    ("isEPPConfigured", 100.0, 50.0),
    ("requiredCoveragePercentage", 100.0, 50.0),
    ("staleSensorCount", 0, 2),
    ("infectedEndpointCount", 0, 1),
]


@pytest.mark.parametrize("key,good,mixed", CASES)
def test_complete_read(key, good, mixed):
    assert value(key, body(GOOD)) == good
    assert value(key, body(MIXED)) == mixed


def test_string_epochs_and_flags():
    c = {"computerName": "x", "avEngineOnOff": "1", "infected": "0", "lastUpdateTime": str(NEWEST)}
    assert value("isEPPConfigured", body([c])) == 100.0
    assert value("infectedEndpointCount", body([c])) == 0


def test_empty_fleet():
    assert value("isEPPDeployed", body([])) is False
    assert value("staleSensorCount", body([])) == 0
    assert value("requiredCoveragePercentage", body([])) is None
    assert value("isEPPConfigured", body([])) is None


NO_EVIDENCE = [
    None, {}, [], "",
    {"errorCode": "401", "error": "Unauthorized"},
    {"status_code": 401, "message": "Invalid token"},
    {"status": 403, "message": "Forbidden"},
    {"data": {"unrelated": 1}, "validation": {"status": "skipped", "errors": [], "warnings": []}},
    {"data": {"content": [client(1)]}, "validation": {}},
]


@pytest.mark.parametrize("key", [c[0] for c in CASES])
@pytest.mark.parametrize("payload", NO_EVIDENCE)
def test_no_evidence_is_not_measured(key, payload):
    out = load(key)(payload)
    assert out["transformedResponse"][key] is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"


@pytest.mark.parametrize("key", [c[0] for c in CASES])
def test_partial_read_is_not_scored(key):
    assert value(key, body(GOOD, total=2500)) is None
