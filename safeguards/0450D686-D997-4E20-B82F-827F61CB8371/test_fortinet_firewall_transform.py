"""Fortinet firewall_transform: isFirewallEnabled, isFirewallLoggingEnabled and isFirewallConfigured from the FortiOS
firewall/policy cmdb read. Fixtures follow the FortiOS REST body ({"http_method", "results", "vdom", "status",
"http_status"}) and the config firewall policy fields status (enable | disable) and logtraffic (all | utm | disable),
wrapped as Integration-Service returns getFirewallPolicies (policies beside apiResponse). Policy names are synthetic.
Every case asserts the value AND the dataCollection status, typed, stringified, wrapped, and in the RestrictedPython
replica."""
import importlib.util
import json
import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
FILE = os.path.join(HERE, "firewall_transform.py")
KEYS = ("isFirewallEnabled", "isFirewallLoggingEnabled", "isFirewallConfigured")


def load_plain():
    spec = importlib.util.spec_from_file_location("fortinet_firewall_transform", FILE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def load_sandboxed():
    pytest.importorskip("RestrictedPython")
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import restricted_sandbox
    with open(FILE) as fh:
        return restricted_sandbox.load(fh.read())["transform"]


def fortios(results, status="success", http_status=200, **extra):
    body = {"http_method": "GET", "results": results, "vdom": "root", "path": "firewall", "name": "policy",
            "status": status, "http_status": http_status, "serial": "FGVMTEST00000000", "version": "v7.4.3"}
    body.update(extra)
    return body


def pol(pid, status="enable", logtraffic="all"):
    out = {"policyid": pid, "name": "p%d" % pid, "status": status, "action": "accept", "logtraffic": logtraffic}
    if logtraffic is None:
        del out["logtraffic"]
    return out


def is_part(body):
    results = body.get("results") if isinstance(body, dict) else None
    return {"policies": results if isinstance(results, list) else [], "apiResponse": body}


class Poisoned(dict):
    def boom(self, *a, **k):
        raise RuntimeError("every read raises")
    __getitem__ = get = keys = items = values = __iter__ = __contains__ = __len__ = boom


MEASURED = [
    ("enabled, logging all", is_part(fortios([pol(1), pol(2), pol(3, status="disable", logtraffic="disable")])),
     (True, True, True)),
    ("logtraffic absent reads as the documented default utm", is_part(fortios([pol(1, logtraffic=None)])),
     (True, True, True)),
    ("every policy disabled", is_part(fortios([pol(1, status="disable"), pol(2, status="disable")])),
     (False, False, False)),
    ("an enabled policy with logging disabled", is_part(fortios([pol(1), pol(2, logtraffic="disable")])),
     (True, False, False)),
]

NO_EVIDENCE = [
    ("empty results", is_part(fortios([]))),
    ("FortiOS 403", is_part({"http_method": "GET", "status": "error", "http_status": 403})),
    ("vendor error as response", {"vendorErrorAsResponse": {"status": 403, "message": "permission denied"}}),
    ("partial read", is_part(fortios([pol(1)], matched_count=40))),
    ("only the returnSpec default", {"policies": []}),
    ("empty dict", {}),
    ("empty string", ""),
    ("the old self-answer field and nothing else", {"isFirewallEnabled": True, "isFirewallLoggingEnabled": True}),
]


def shapes(body):
    yield body
    yield json.dumps(body)
    yield {"data": body, "validation": {"status": "passed", "errors": [], "warnings": []}}


@pytest.fixture(params=["plain", "sandboxed"])
def tx(request):
    return load_plain() if request.param == "plain" else load_sandboxed()


@pytest.mark.parametrize("name,body,want", MEASURED, ids=[c[0] for c in MEASURED])
def test_measured(tx, name, body, want):
    for shape in shapes(body):
        out = tx(shape)
        assert out["additionalInfo"]["dataCollection"]["status"] == "success"
        assert tuple(out["transformedResponse"][k] for k in KEYS) == want


@pytest.mark.parametrize("name,body", NO_EVIDENCE, ids=[c[0] for c in NO_EVIDENCE])
def test_no_evidence_is_not_evaluated(tx, name, body):
    for shape in shapes(body):
        out = tx(shape)
        assert out["additionalInfo"]["dataCollection"]["status"] == "error"
        assert out["additionalInfo"]["dataCollection"]["errors"]
        for k in KEYS:
            assert out["transformedResponse"][k] is None


def test_poisoned_body_is_not_evaluated(tx):
    out = tx(Poisoned())
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"
    for k in KEYS:
        assert out["transformedResponse"][k] is None
