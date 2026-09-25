"""Trend Vision One endpoint-inventory checks, on the documented response shape of
GET /v3.0/endpointSecurity/endpoints. No live payload yet: each check has a passing
body, a flip that must fail, and the fail-closed bodies."""
import importlib.util
import pathlib

import pytest

HERE = pathlib.Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location("tmv1_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def ep(name, type_="desktop", iso="off", epp="on", ver="latestVersion", edr="enabled", conn="connected"):
    e = {"agentGuid": name, "endpointName": name, "type": type_, "isolationStatus": iso}
    if epp is not None:
        e["eppAgent"] = {"status": epp, "componentVersion": ver}
    if edr is not None:
        e["edrSensor"] = {"status": edr, "connectivity": conn}
    return e


def body(*eps, next_link=None):
    b = {"items": list(eps)}
    if next_link:
        b["nextLink"] = next_link
    return b


GOOD = body(ep("ws1"), ep("srv1", type_="server"))

CASES = [
    ("iseppdeployed", "isEPPDeployed", True, body(ep("ws1"), ep("ws2", epp=None)), False),
    ("isedrdeployed", "isEDRDeployed", True, body(ep("ws1"), ep("ws2", edr="enabling")), False),
    ("issignatureuptodate", "isSignatureUpToDate", True, body(ep("ws1", ver="outdatedVersion")), False),
    ("iseppenabledforcriticalsystems", "isEPPEnabledForCriticalSystems", True,
     body(ep("srv1", type_="server", epp="off")), False),
    ("isolatedendpointcount", "isolatedEndpointCount", 0, body(ep("ws1", iso="on"), ep("ws2")), 1),
    ("offlinesensorcount", "offlineSensorCount", 0, body(ep("ws1", conn="disconnected")), 1),
]

BAD_BODIES = [{}, None, "{}", body(), {"error": {"code": "Unauthorized", "message": "x"}},
              body(ep("ws1"), next_link="https://api.xdr.trendmicro.com/v3.0/endpointSecurity/endpoints?skipToken=x")]


@pytest.mark.parametrize("name,key,good,flip,flipped", CASES)
def test_good_and_flip(name, key, good, flip, flipped):
    module = load(name)
    assert module.transform(GOOD)["transformedResponse"][key] == good
    assert module.transform(flip)["transformedResponse"][key] == flipped


@pytest.mark.parametrize("name,key,good,flip,flipped", CASES)
def test_fail_closed(name, key, good, flip, flipped):
    module = load(name)
    fail_value = None if key.endswith("Count") else False
    for bad in BAD_BODIES:
        assert module.transform(bad)["transformedResponse"][key] is fail_value
