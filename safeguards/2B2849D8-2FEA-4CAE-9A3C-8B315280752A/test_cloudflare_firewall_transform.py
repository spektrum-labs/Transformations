"""Cloudflare firewall_transform: isFirewallEnabled from the zone's custom firewall rules. The pass fixture is the 200
example Cloudflare publishes for GET /zones/{zone_id}/firewall/rules; the others change one field of it, or follow the
Rulesets API entry point body ("result": {"phase", "rules"}) the definition is meant to move to. Wrapped as
Integration-Service returns getFirewallRules (rules beside apiResponse). Every case asserts the value AND the
dataCollection status, typed, stringified, wrapped, and in the RestrictedPython replica."""
import copy
import importlib.util
import json
import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
FILE = os.path.join(HERE, "firewall_transform.py")
KEY = "isFirewallEnabled"

VENDOR_EXAMPLE = {
    "errors": [{"code": 1000, "message": "message", "documentation_url": "documentation_url",
                "source": {"pointer": "pointer"}}],
    "messages": [{"code": 1000, "message": "message", "documentation_url": "documentation_url",
                  "source": {"pointer": "pointer"}}],
    "result": [{
        "id": "372e67954025e0ba6aaa6d586b9e0b60", "action": "block",
        "description": "Blocks traffic identified during investigation for MIR-31",
        "filter": {"id": "372e67954025e0ba6aaa6d586b9e0b61",
                   "description": "Restrict access from these browsers on this address range.",
                   "expression": "(http.request.uri.path ~ \".*wp-login.php\") and ip.addr ne 172.16.22.155",
                   "paused": False, "ref": "FIL-100"},
        "paused": False, "priority": 50, "products": ["waf"], "ref": "MIR-31"}],
    "success": True,
    "result_info": {"count": 1, "page": 1, "per_page": 20, "total_count": 2000},
}


def load_plain():
    spec = importlib.util.spec_from_file_location("cloudflare_firewall_transform", FILE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def load_sandboxed():
    pytest.importorskip("RestrictedPython")
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import restricted_sandbox
    with open(FILE) as fh:
        return restricted_sandbox.load(fh.read())["transform"]


def is_part(body):
    result = body.get("result") if isinstance(body, dict) else None
    return {"rules": result if isinstance(result, list) else [], "apiResponse": body}


def legacy(rules, total=None):
    body = copy.deepcopy(VENDOR_EXAMPLE)
    body["result"] = rules
    body["result_info"] = {"count": len(rules), "page": 1, "per_page": 20,
                           "total_count": len(rules) if total is None else total}
    return body


def rule(**changes):
    out = copy.deepcopy(VENDOR_EXAMPLE["result"][0])
    out.update(changes)
    return out


def ruleset(rules):
    return {"errors": [], "messages": [], "success": True,
            "result": {"id": "2f2feab2026849078ba485f918791bdc", "kind": "zone", "name": "default",
                       "phase": "http_request_firewall_custom", "rules": rules}}


def rs_rule(action, enabled=True):
    return {"id": "r1", "version": "1", "action": action, "expression": "ip.src.asnum eq 64496", "enabled": enabled}


class Poisoned(dict):
    def boom(self, *a, **k):
        raise RuntimeError("every read raises")
    __getitem__ = get = keys = items = values = __iter__ = __contains__ = __len__ = boom


MEASURED = [
    ("vendor example verbatim: one active block rule on a partial page", is_part(VENDOR_EXAMPLE), True),
    ("rulesets: an enabled block rule", {"rules": [], "apiResponse": ruleset([rs_rule("block")])}, True),
    ("every rule paused", is_part(legacy([rule(paused=True), rule(id="b", paused=True)])), False),
    ("the rule's filter paused", is_part(legacy([rule(filter=dict(VENDOR_EXAMPLE["result"][0]["filter"],
                                                                   paused=True))])), False),
    ("only allow and log rules", is_part(legacy([rule(action="allow"), rule(id="b", action="log")])), False),
    ("rulesets: the only rule disabled", {"rules": [], "apiResponse": ruleset([rs_rule("block", False)])}, False),
]

NO_EVIDENCE = [
    ("no rules", is_part(legacy([]))),
    ("success false", is_part({"success": False, "errors": [{"code": 10000, "message": "Authentication error"}],
                               "messages": [], "result": None})),
    ("partial page with no enforcing rule", is_part(legacy([rule(paused=True)], total=150))),
    ("vendor error as response", {"vendorErrorAsResponse": {"status": 403, "message": "permission denied"}}),
    ("only the returnSpec default", {"rules": []}),
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
        assert out["transformedResponse"][KEY] is want


@pytest.mark.parametrize("name,body", NO_EVIDENCE, ids=[c[0] for c in NO_EVIDENCE])
def test_no_evidence_is_not_evaluated(tx, name, body):
    for shape in shapes(body):
        out = tx(shape)
        assert out["additionalInfo"]["dataCollection"]["status"] == "error"
        assert out["additionalInfo"]["dataCollection"]["errors"]
        assert out["transformedResponse"][KEY] is None


def test_poisoned_body_is_not_evaluated(tx):
    out = tx(Poisoned())
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"
    assert out["transformedResponse"][KEY] is None


def test_logging_is_not_answered_from_this_endpoint(tx):
    # Neither Cloudflare API carries a field evidencing firewall event logging: the criterion is document-only.
    assert "isFirewallLoggingEnabled" not in tx(is_part(VENDOR_EXAMPLE))["transformedResponse"]
