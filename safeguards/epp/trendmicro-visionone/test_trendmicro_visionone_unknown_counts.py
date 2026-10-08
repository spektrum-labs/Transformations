"""A count Trend Vision One does not make known is not evaluated, never a failed check (2 Oct 2026).

On a real customer estate, isolatedEndpointCount, contentVersionDriftCount and endpointOperationalStatusUnprotectedCount
returned None (some endpoints report no known isolation, version or agent status) with dataCollection "success",
so the platform stored them as Failed. A None count must carry a dataCollection error. Built on the real
response shape in fixture_endpoints_real_shape.json.
"""
import copy
import importlib.util
import json
import pathlib

import pytest

HERE = pathlib.Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location("tmv1_unknown_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def body():
    return json.loads((HERE / "fixture_endpoints_real_shape.json").read_text())


def items(data):
    return data["items"] if isinstance(data, dict) and "items" in data else data


def unknown_isolation(data):
    items(data)[0]["isolationStatus"] = "unknown"
    return data


def unknown_version(data):
    for e in items(data):
        agent = e.get("eppAgent")
        if isinstance(agent, dict) and agent.get("componentVersion"):
            agent["componentVersion"] = "unknownVersions"
            break
    return data


def unknown_agent_status(data):
    for e in items(data):
        agent = e.get("eppAgent")
        if isinstance(agent, dict) and agent.get("status") in ("on", "off"):
            agent["status"] = "unknown"
            break
    return data


CASES = [
    ("isolatedendpointcount", "isolatedEndpointCount", unknown_isolation),
    ("contentversiondriftcount", "contentVersionDriftCount", unknown_version),
    ("endpointoperationalstatusunprotectedcount", "endpointOperationalStatusUnprotectedCount", unknown_agent_status),
]


@pytest.mark.parametrize("name,key,make_unknown", CASES)
def test_unknown_count_is_a_data_collection_error(name, key, make_unknown):
    out = load(name).transform(make_unknown(copy.deepcopy(body())))
    assert out["transformedResponse"][key] is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"
    assert out["additionalInfo"]["dataCollection"]["errors"]


@pytest.mark.parametrize("name,key,make_unknown", CASES)
def test_known_count_stays_a_measurement(name, key, make_unknown):
    out = load(name).transform(copy.deepcopy(body()))
    value = out["transformedResponse"][key]
    if value is not None:
        assert isinstance(value, int)
        assert out["additionalInfo"]["dataCollection"]["status"] == "success"


@pytest.mark.parametrize("name,key,make_unknown", CASES)
def test_empty_estate_is_a_data_collection_error(name, key, make_unknown):
    data = copy.deepcopy(body())
    if isinstance(data, dict) and "items" in data:
        data["items"] = []
    else:
        data = []
    out = load(name).transform(data)
    assert out["transformedResponse"][key] is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"
