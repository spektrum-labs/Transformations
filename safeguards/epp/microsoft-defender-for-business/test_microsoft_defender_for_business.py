"""Microsoft Defender for Business (Endpoint Security): isEPPDeployed, requiredCoveragePercentage, totalEndpointCount.

Fixture bodies follow the List machines response on
https://learn.microsoft.com/en-us/defender-endpoint/api/get-machines .
"""
import importlib.util
from pathlib import Path

import pytest


def load(name):
    spec = importlib.util.spec_from_file_location("mdb_" + name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


DEPLOYED = load("isEPPDeployed")
COVERAGE = load("requiredCoveragePercentage")
TOTAL = load("totalEndpointCount")


def machine(i, status):
    return {"id": "m%d" % i, "computerDnsName": "pc%d.contoso.com" % i, "osPlatform": "Windows11",
            "healthStatus": "Active", "onboardingStatus": status, "riskScore": "Low"}


def machines(onboarded, discovered, unsupported=0):
    items = [machine(i, "Onboarded") for i in range(onboarded)]
    items = items + [machine(100 + i, "CanBeOnboarded") for i in range(discovered)]
    items = items + [machine(200 + i, "Unsupported") for i in range(unsupported)]
    return {"@odata.context": "https://api.security.microsoft.com/api/$metadata#Machines", "value": items}


def run(module, key, payload):
    out = module.transform(payload)
    return out["transformedResponse"][key], out["additionalInfo"]["dataCollection"]["status"]


# --- real shapes ---------------------------------------------------------------------------------------------

def test_onboarded_fleet():
    body = machines(37, 3, unsupported=2)
    assert run(DEPLOYED, "isEPPDeployed", body) == (True, "success")
    assert run(COVERAGE, "requiredCoveragePercentage", body) == (92.5, "success")
    assert run(TOTAL, "totalEndpointCount", body) == (37, "success")


def test_coverage_rounds_down():
    # 2 / 3 = 66.66.. -> 66.6
    assert run(COVERAGE, "requiredCoveragePercentage", machines(2, 1)) == (66.6, "success")
    assert run(COVERAGE, "requiredCoveragePercentage", machines(12, 0)) == (100.0, "success")


def test_nothing_onboarded_is_measured():
    body = machines(0, 4)
    assert run(DEPLOYED, "isEPPDeployed", body) == (False, "success")
    assert run(COVERAGE, "requiredCoveragePercentage", body) == (0.0, "success")
    assert run(TOTAL, "totalEndpointCount", body) == (0, "success")


def test_empty_list_is_measured_zero_but_no_coverage():
    body = machines(0, 0)
    assert run(DEPLOYED, "isEPPDeployed", body) == (False, "success")
    assert run(TOTAL, "totalEndpointCount", body) == (0, "success")
    assert run(COVERAGE, "requiredCoveragePercentage", body) == (None, "error")


def test_lowercase_onboardingstatus_spelling():
    body = {"value": [{"id": "m1", "onboardingstatus": "onboarded"}]}
    assert run(TOTAL, "totalEndpointCount", body) == (1, "success")


# --- empty, error and partial shapes: never an answer ----------------------------------------------------------

NO_EVIDENCE = {
    "null": None,
    "empty_dict": {},
    "empty_string": "",
    "defender_403": {"error": {"code": "Forbidden", "message": "Missing application roles: Machine.Read.All"}},
    "not_found_404": {"statusCode": 404, "error": "Not Found"},
    "auth_401": {"statusCode": 401, "error": "Unauthorized"},
    "unrelated": {"hello": "world"},
    "paged": dict(machines(5, 0), **{"@odata.nextLink": "https://api.security.microsoft.com/api/machines?$skip=10000"}),
}

CASES = [(DEPLOYED, "isEPPDeployed"), (COVERAGE, "requiredCoveragePercentage"), (TOTAL, "totalEndpointCount")]


@pytest.mark.parametrize("name", sorted(NO_EVIDENCE))
@pytest.mark.parametrize("module,key", CASES, ids=[k for m, k in CASES])
def test_no_evidence_is_unevaluated(module, key, name):
    assert run(module, key, NO_EVIDENCE[name]) == (None, "error")
