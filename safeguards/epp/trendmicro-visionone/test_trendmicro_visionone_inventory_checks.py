"""Seven more Trend Vision One checks on GET /v3.0/endpointSecurity/endpoints, tested on a real
tenant response (fixture_endpoints_real_shape.json: 32 of 417 items from a 2026-09-25 capture,
identifiers replaced, every status/version/policy field verbatim), a healthy rewrite of it, a
flip that must change the verdict, and the fail-closed bodies."""
import copy
import importlib.util
import json
import pathlib
from datetime import datetime, timedelta

import pytest

HERE = pathlib.Path(__file__).resolve().parent
CAPTURED = datetime(2026, 9, 25, 14, 53, 38)


def load(name):
    spec = importlib.util.spec_from_file_location("tmv1_more_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def real():
    """The captured body with sensor timestamps shifted so each keeps its age at capture."""
    body = json.loads((HERE / "fixture_endpoints_real_shape.json").read_text())
    shift = datetime.utcnow() - CAPTURED
    for e in body["items"]:
        sensor = e.get("edrSensor")
        if sensor and sensor.get("lastConnectedDateTime"):
            seen = datetime.fromisoformat(sensor["lastConnectedDateTime"]) + shift
            sensor["lastConnectedDateTime"] = seen.strftime("%Y-%m-%dT%H:%M:%S")
    return body


def healthy():
    body = real()
    fresh = (datetime.utcnow() - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S")
    for e in body["items"]:
        agent = e["eppAgent"]
        agent["version"] = agent.get("version") or "6.7.4194"
        agent["protectionManager"] = agent.get("protectionManager") or "Trend Micro Worry-Free Business Security Services"
        agent["status"] = "on"
        agent["componentVersion"] = "latestVersion"
        agent["policyName"] = "Standard"
        e["edrSensor"] = dict(e.get("edrSensor") or {}, status="enabled", connectivity="connected",
                              lastConnectedDateTime=fresh)
    return body


def first(change):
    body = healthy()
    change(body["items"][0])
    return body


OLD = (datetime.utcnow() - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S")

# file, key, verdict on the real capture, verdict on healthy, flip of healthy, verdict on flip
CASES = [
    ("isdeviceosversionvisible", "isDeviceOSVersionVisible", True, True,
     lambda: first(lambda e: e.update(osVersion="")), False),
    ("iseppenabled", "isEPPEnabled", False, True,
     lambda: first(lambda e: e["eppAgent"].update(status="unknown")), False),
    ("iseppconfigured", "isEPPConfigured", False, True,
     lambda: first(lambda e: e["eppAgent"].update(policyName="")), False),
    ("endpointoperationalstatusunprotectedcount", "endpointOperationalStatusUnprotectedCount", None, 0,
     lambda: first(lambda e: e["eppAgent"].update(version="", protectionManager="")), 1),
    ("contentversiondriftcount", "contentVersionDriftCount", None, 0,
     lambda: first(lambda e: e["eppAgent"].update(componentVersion="outdatedVersion")), 1),
    ("stalesensorcount", "staleSensorCount", 4, 0,
     lambda: first(lambda e: e["edrSensor"].update(lastConnectedDateTime=OLD)), 1),
    ("isrecordereventcollectionenabled", "isRecorderEventCollectionEnabled", False, True,
     lambda: first(lambda e: e["edrSensor"].update(connectivity="disconnected")), False),
]

MORE = [
    ("endpointoperationalstatusunprotectedcount", "endpointOperationalStatusUnprotectedCount",
     lambda: first(lambda e: e["eppAgent"].update(status="off")), 1),
    ("endpointoperationalstatusunprotectedcount", "endpointOperationalStatusUnprotectedCount",
     lambda: first(lambda e: e["eppAgent"].update(status="unknown")), None),
    ("contentversiondriftcount", "contentVersionDriftCount",
     lambda: first(lambda e: e["eppAgent"].update(componentVersion="unknownVersions")), None),
    ("contentversiondriftcount", "contentVersionDriftCount",
     lambda: first(lambda e: e["eppAgent"].update(componentVersion="controlledLatestVersion")), 0),
    ("stalesensorcount", "staleSensorCount",
     lambda: first(lambda e: e["edrSensor"].update(lastConnectedDateTime="")), None),
    ("stalesensorcount", "staleSensorCount",
     lambda: first(lambda e: e["edrSensor"].update(lastConnectedDateTime=OLD + "Z")), 1),
    ("iseppenabled", "isEPPEnabled",
     lambda: first(lambda e: e["eppAgent"].update(version="", protectionManager="")), False),
    ("isrecordereventcollectionenabled", "isRecorderEventCollectionEnabled",
     lambda: first(lambda e: e.pop("edrSensor")), False),
    ("isdeviceosversionvisible", "isDeviceOSVersionVisible",
     lambda: first(lambda e: e.pop("osName")), False),
]

BAD_BODIES = [
    {}, None, "{}", {"items": []},
    {"error": {"code": "Unauthorized", "message": "Invalid token"}},
    {"status": "Error", "message": "vendor 401"},
    {"response": {"error": {"code": "Forbidden", "message": "no permission"}}},
]


def verdict(name, key, body):
    return load(name).transform(body)["transformedResponse"][key]


def same(got, expected):
    """0 == False in Python; a count must not come back as a boolean or the reverse."""
    return got == expected and type(got) is type(expected)


@pytest.mark.parametrize("name,key,on_real,on_healthy,flip,on_flip", CASES)
def test_real_healthy_and_flip(name, key, on_real, on_healthy, flip, on_flip):
    assert same(verdict(name, key, real()), on_real)
    assert same(verdict(name, key, healthy()), on_healthy)
    assert same(verdict(name, key, flip()), on_flip)


@pytest.mark.parametrize("name,key,body,expected", MORE)
def test_more_legs(name, key, body, expected):
    assert same(verdict(name, key, body()), expected)


@pytest.mark.parametrize("name,key,on_real,on_healthy,flip,on_flip", CASES)
def test_fail_closed(name, key, on_real, on_healthy, flip, on_flip):
    fail_value = None if key.endswith("Count") else False
    for bad in BAD_BODIES + [dict(healthy(), nextLink="https://api.xdr.trendmicro.com/v3.0/endpointSecurity/endpoints?skipToken=x")]:
        assert verdict(name, key, copy.deepcopy(bad)) is fail_value
