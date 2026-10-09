"""An empty Defender machine inventory is Not evaluated (None), never a fail.

For each of the Defender endpoint transforms: an empty inventory gives None plus a dataCollection
error (so the evaluator reads it as not evaluated), one real failing device gives False (or 0), and an
all-healthy fleet gives True. Synthetic data only.
"""
import importlib.util
from pathlib import Path

import pytest


def load(name):
    spec = importlib.util.spec_from_file_location("emp_" + name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def machine(onboarding="Onboarded", health="Active"):
    return {"osPlatform": "Windows11", "onboardingStatus": onboarding, "healthStatus": health,
            "isExcluded": False, "lastSeen": "2026-01-01T00:00:00Z"}


EMPTY = {"value": []}
NOT_ONBOARDED = {"value": [dict(machine("CanBeOnboarded", "Unknown"), osPlatform="WindowsServer2022")]}
UNHEALTHY_SENSOR = {"value": [machine("Onboarded", "NoSensorData")]}
ALL_HEALTHY = {"value": [machine(), dict(machine(), osPlatform="WindowsServer2022")]}

# (module, criterion, body with one real failing device, its value, value for the healthy fleet)
CASES = [
    ("microsoft_endpoint_edrdeployed", "isEDRDeployed", NOT_ONBOARDED, False, True),
    ("microsoft_endpoint_oneclick", "isEPPEnabled", NOT_ONBOARDED, False, True),
    ("microsoft_endpoint_iseppconfigured", "isEPPConfigured", UNHEALTHY_SENSOR, 0, 100),
    ("microsoft_endpoint_servercoverage", "serverCoveragePercentage", NOT_ONBOARDED, 0, 100),
]
IDS = [case[1] for case in CASES]


@pytest.mark.parametrize("name,key,body,unhealthy,healthy", CASES, ids=IDS)
def test_empty_inventory_is_none_and_not_evaluated(name, key, body, unhealthy, healthy):
    out = load(name).transform(EMPTY)
    assert out["transformedResponse"][key] is None
    info = out["additionalInfo"]
    assert info["dataCollection"]["status"] == "error"
    assert info["dataCollection"]["errors"] == ["Defender has no onboarded devices"]
    assert info["evaluation"]["recommendations"]


@pytest.mark.parametrize("name,key,body,unhealthy,healthy", CASES, ids=IDS)
def test_one_real_unhealthy_device_is_a_fail(name, key, body, unhealthy, healthy):
    out = load(name).transform(ONE_UNHEALTHY)
    got = out["transformedResponse"][key]
    assert got == unhealthy and got is not None
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"


@pytest.mark.parametrize("name,key,body,unhealthy,healthy", CASES, ids=IDS)
def test_all_healthy_devices_pass(name, key, body, unhealthy, healthy):
    out = load(name).transform(ALL_HEALTHY)
    assert out["transformedResponse"][key] == healthy
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"
