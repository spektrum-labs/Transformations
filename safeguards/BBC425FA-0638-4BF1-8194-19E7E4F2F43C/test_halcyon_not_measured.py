"""Halcyon (Endpoint Security): keys no routed vendor body answers read Unevaluated.

These files answered each criterion from a field of its own name (`data.get('<key>', ...)`).
Halcyon's definition does not route a vendor body that answers them. Every key must be None with
dataCollection.status "error" on every body, including one that used to pass, and the reason must
name Halcyon. Synthetic data only.
"""
import importlib.util
import os

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))

FILES = {
    "epp_transform": ("isEPPEnabled", "isEPPDeployed", "isEPPLoggingEnabled", "isEPPEnabledForCriticalSystems",
                      "isEDRDeployed", "isEndpointSecurityEnabled", "isMDREnabled", "isMDRLoggingEnabled",
                      "requiredCoveragePercentage", "requiredConfigurationPercentage", "isEPPConfigured"),
    "isbehavioralmonitoringvalid": ("isBehavioralMonitoringValid",),
    "isidpenabled": ("isSSOEnabled", "isSSOEnabledMDR"),
    "ispatchmanagementenabled": ("isPatchManagementEnabled", "isPatchManagementValid"),
    "isremovablemediacontrolled": ("isRemovableMediaControlled",),
}


def load(name):
    spec = importlib.util.spec_from_file_location("halcyon_" + name, os.path.join(HERE, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Poisoned(dict):
    """A non-empty object whose every read raises, to drive any except path."""

    def __init__(self):
        super().__init__(poisoned=True)

    def boom(self, *args, **kwargs):
        raise RuntimeError("poisoned read")

    get = __getitem__ = __contains__ = keys = items = values = __iter__ = boom

    def __len__(self):
        return 1


DEVICES = {"count": 1, "items": [{"id": "00000000-0000-0000-0000-00000000000a", "name": "WS-SYNTH-01",
                                   "state": "Online"}]}

BODIES = {
    "empty": lambda: {},
    "none": lambda: None,
    # every one of these read True before: a non-empty collection, or the key itself
    "items": lambda: {"items": [{"id": 1}]},
    "self-answer": lambda: {key: True for keys in FILES.values() for key in keys},
    "devices": lambda: DEVICES,
    "poisoned": lambda: Poisoned(),
}


@pytest.mark.parametrize("name", sorted(FILES))
@pytest.mark.parametrize("case", sorted(BODIES))
def test_every_key_is_unevaluated(name, case):
    out = load(name).transform(BODIES[case]())
    collection = out["additionalInfo"]["dataCollection"]
    assert collection["status"] == "error"
    assert collection["errors"] and all(isinstance(e, str) and e for e in collection["errors"])
    for key in FILES[name]:
        assert key in out["transformedResponse"]
        assert out["transformedResponse"][key] is None
    for text in collection["errors"]:
        assert "Halcyon" in text
        assert "Arctic" not in text and "Aurora" not in text
    assert out["additionalInfo"]["metadata"]["vendor"] == "Halcyon"
