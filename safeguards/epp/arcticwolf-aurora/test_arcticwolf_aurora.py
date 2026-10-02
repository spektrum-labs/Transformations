"""Aurora (Cylance) transforms against bodies shaped like the documented responses.

Shapes from the Arctic Wolf Aurora Endpoint Defense API docs:
Get Devices Extended (GET /devices/v2) and Get Device Count (GET /devices/v2/products).
"""
import importlib.util
from pathlib import Path

import pytest

HERE = Path(__file__).parent


def load(name):
    spec = importlib.util.spec_from_file_location("aw_" + name, HERE / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def dev(products=("protect",), policy="pol-1", bg=True):
    d = {"id": "d", "name": "host", "state": "Online", "products": [{"name": p, "version": "3.2", "status": "Online"} for p in products]}
    if policy:
        d["policy"] = {"id": policy, "name": "Default"}
    if bg is not None:
        d["background_detection"] = bg
    return d


def page(*items):
    return {"page_number": 1, "page_size": 200, "total_number_of_items": len(items), "total_pages": 1, "page_items": list(items)}


def result(name, body, key):
    return load(name).transform(body)["transformedResponse"][key]


EMPTY = [None, {}, [], "", "not json", {"error": "unauthorized"}, {"apiResponse": {}}]


@pytest.mark.parametrize("body", EMPTY)
@pytest.mark.parametrize("name,key", [("confirmedlicensepurchased", "confirmedLicensePurchased"), ("iseppdeployed", "isEPPDeployed"),
                                      ("isedrdeployed", "isEDRDeployed"), ("iseppconfigured", "isEPPConfigured"),
                                      ("isbehavioralmonitoringvalid", "isBehavioralMonitoringValid")])
def test_bodies_that_prove_nothing_are_false(name, key, body):
    assert result(name, body, key) is False


def test_license():
    assert result("confirmedlicensepurchased", [{"name": "protect", "version": "3.2", "count": 12}], "confirmedLicensePurchased") is True
    assert result("confirmedlicensepurchased", {"apiResponse": [{"name": "protect", "version": "3.2", "count": 0}]}, "confirmedLicensePurchased") is False


def test_epp_and_edr_deployed():
    assert result("iseppdeployed", page(dev(("protect",))), "isEPPDeployed") is True
    assert result("iseppdeployed", page(dev(("optics",))), "isEPPDeployed") is False
    assert result("isedrdeployed", page(dev(("protect", "optics"))), "isEDRDeployed") is True
    assert result("isedrdeployed", page(dev(("protect",))), "isEDRDeployed") is False


def test_policy_assignment():
    assert result("iseppconfigured", page(dev(), dev()), "isEPPConfigured") is True
    assert result("iseppconfigured", page(dev(), dev(policy=None)), "isEPPConfigured") is False


def test_background_detection():
    assert result("isbehavioralmonitoringvalid", page(dev(), dev()), "isBehavioralMonitoringValid") is True
    assert result("isbehavioralmonitoringvalid", page(dev(), dev(bg=False)), "isBehavioralMonitoringValid") is False
    assert result("isbehavioralmonitoringvalid", page(dev(), dev(bg=None)), "isBehavioralMonitoringValid") is False
