"""Arctic Wolf - EDR Endpoint Security: keys no wired Aurora endpoint can answer read Unevaluated.

These files answered each criterion from a field of its own name (`data.get('<key>', ...)`), and
epp_transform.py parsed Sophos Central fields. The definition's checkInstalled and
getIdentityProvider methods define no request, so no vendor body reaches them. Every key must be
None with dataCollection.status "error" on every body, including one that used to pass.
Synthetic data only.
"""
import importlib.util
import os

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))

FILES = {
    "epp_transform": ("isEPPConfigured", "isEDRDeployed", "isEPPDeployed"),
    "isbehavioralmonitoringvalid": ("isBehavioralMonitoringValid",),
    "isidpenabled": ("isSSOEnabled",),
    "ispatchmanagementenabled": ("isPatchManagementEnabled", "isPatchManagementValid"),
    "isremovablemediacontrolled": ("isRemovableMediaControlled",),
}


def load(name):
    spec = importlib.util.spec_from_file_location("arcticwolf_edr_" + name, os.path.join(HERE, name + ".py"))
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


AURORA_DEVICES = {"page_number": 1, "page_size": 200, "total_pages": 1, "total_number_of_items": 1,
                  "page_items": [{"id": "00000000-0000-0000-0000-00000000000a", "name": "WS-SYNTH-01",
                                  "state": "Online", "agent_version": "3.0.0",
                                  "policy": {"id": "pol-1", "name": "Default"},
                                  "products": [{"name": "protect", "version": "3.0.0", "status": "Online"}],
                                  "background_detection": True, "is_safe": True}]}

BODIES = {
    "empty": lambda: {},
    "none": lambda: None,
    # every one of these read True before: a non-empty collection, or the key itself
    "items": lambda: {"items": [{"id": 1}]},
    "self-answer": lambda: {key: True for keys in FILES.values() for key in keys},
    "aurora-devices": lambda: AURORA_DEVICES,
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
