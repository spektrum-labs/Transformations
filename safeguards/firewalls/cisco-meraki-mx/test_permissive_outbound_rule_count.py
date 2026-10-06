"""Cisco Meraki MX permissiveOutboundRuleCount (NSF-003): fixtures follow the
firewallRulesByNetwork workflow result ({"networks": [...], "l3FirewallRules": [...]}) and Meraki's documented
L3 rules shape, including the implicit "Default rule" the GET appends. Network names are synthetic. Every case
runs typed, stringified (as Token-Service stores it), Token-Service-wrapped, and through the RestrictedPython
replica."""
import importlib.util
import json
import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
FILE = os.path.join(HERE, "permissiveOutboundRuleCount.py")
KEY = "permissiveOutboundRuleCount"


def load_plain():
    spec = importlib.util.spec_from_file_location("meraki_permissive_outbound", FILE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_sandboxed():
    pytest.importorskip("RestrictedPython")
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import restricted_sandbox
    with open(FILE) as fh:
        return restricted_sandbox.load(fh.read())["transform"]


def run(body, transform=None):
    return (transform or load_plain().transform)(body)


def value(body, transform=None):
    return run(body, transform)["transformedResponse"][KEY]


def rule(policy, protocol="tcp", dest_port="443", dest="Any", src="Any", comment=""):
    return {"comment": comment, "policy": policy, "protocol": protocol, "srcPort": "Any", "srcCidr": src,
            "destPort": dest_port, "destCidr": dest, "syslogEnabled": False}


DEFAULT = {"comment": "Default rule", "policy": "allow", "protocol": "Any", "srcPort": "Any", "srcCidr": "Any",
           "destPort": "Any", "destCidr": "Any", "syslogEnabled": False}
DENY_ALL = rule("deny", "any", "Any", comment="deny everything else")


def locked(name):
    return {"rules": [rule("allow", "tcp", "80,443", comment="web"), rule("allow", "udp", "53", "192.0.2.53/32",
                                                                          comment="dns"), DENY_ALL, DEFAULT]}


def workflow(responses):
    networks = [{"id": "N_%d" % i, "name": "site-%d" % i, "productTypes": ["appliance"]} for i in range(len(responses))]
    return {"networks": networks, "l3FirewallRules": responses}


PASSING = workflow([locked("a"), locked("b")])
FAILING = workflow([locked("a"), {"rules": [rule("allow", "tcp", "443"), DEFAULT]},
                    {"rules": [rule("allow", "any", "Any", comment="servers out", src="10.1.0.0/24"), DENY_ALL, DEFAULT]}])


def stringify(value):
    if isinstance(value, dict):
        return {k: stringify(v) for k, v in value.items()}
    if isinstance(value, list):
        return [stringify(v) for v in value]
    return str(value)


def ts_wrap(body):
    return {"data": {"apiResponse": body}, "validation": {"status": "skipped", "errors": [], "warnings": []}}


@pytest.mark.parametrize("form", ["typed", "stringified", "wrapped", "json-string"])
@pytest.mark.parametrize("loader", ["plain", "sandboxed"])
def test_pass_and_fail(form, loader):
    transform = load_plain().transform if loader == "plain" else load_sandboxed()
    good, bad = PASSING, FAILING
    if form == "stringified":
        good, bad = stringify(good), stringify(bad)
    if form == "wrapped":
        good, bad = ts_wrap(good), ts_wrap(bad)
    if form == "json-string":
        good, bad = json.dumps(good), json.dumps(bad)
    out_good = run(good, transform)
    assert out_good["transformedResponse"][KEY] == 0
    assert out_good["additionalInfo"]["dataCollection"]["status"] == "success"
    out_bad = run(bad, transform)
    assert out_bad["transformedResponse"][KEY] == 2
    reason = out_bad["additionalInfo"]["evaluation"]["failReasons"][0]
    assert "site-1 rule 2 'Default rule'" in reason
    assert "site-2 rule 1 'servers out'" in reason


NO_EVIDENCE = [
    {}, None, "", "{}", "not json",
    {"error": {"type": "authentication_error", "message": "invalid credentials"}},
    {"statusCode": 401, "error": "Unauthorized"},
    {"status_code": 401, "error": "Unauthorized"},
    {"error": {"statusCode": 401, "message": "Unauthorized"}},
    {"statusCode": 403, "error": "Forbidden"},
    {"errors": ["API key does not have access"]},
    {"hello": "world"},
    {"foo": {"bar": [1, 2, 3]}},
    {"networks": []},
    {"l3FirewallRules": []},
    workflow([]),
]


@pytest.mark.parametrize("body", NO_EVIDENCE)
def test_no_evidence_is_not_evaluated(body):
    for wrapped in (body, ts_wrap(body)):
        out = run(wrapped)
        assert out["transformedResponse"][KEY] is None
        assert out["additionalInfo"]["dataCollection"]["status"] == "error"
        assert out["additionalInfo"]["dataCollection"]["errors"]


def test_partial_reads_are_not_evaluated():
    # one network's rules call failed
    assert value(workflow([locked("a"), {"errors": ["Forbidden"]}])) is None
    assert value(workflow([locked("a"), {"error": True, "message": "HTTP 429"}])) is None
    # a missing response
    body = workflow([locked("a"), locked("b")])
    body["l3FirewallRules"] = body["l3FirewallRules"][:1]
    assert value(body) is None
    # an empty rules list (Meraki always returns the Default rule)
    assert value(workflow([{"rules": []}])) is None
    # a full first page of networks
    big = workflow([locked("x")] * 1000)
    assert value(big) is None


def test_rules_below_a_deny_all_are_unreachable():
    body = workflow([{"rules": [DENY_ALL, rule("allow", "any", "Any"), DEFAULT]}])
    assert value(body) == 0


def test_default_rule_counts_when_reached():
    assert value(workflow([{"rules": [DEFAULT]}])) == 1


def test_specific_destination_or_port_is_not_permissive():
    body = workflow([{"rules": [rule("allow", "any", "Any", dest="203.0.113.0/24"), rule("allow", "tcp", "22"),
                                DENY_ALL, DEFAULT]}])
    assert value(body) == 0


def test_tcp_any_port_to_any_is_permissive():
    body = workflow([{"rules": [rule("allow", "tcp", "Any"), DENY_ALL, DEFAULT]}])
    assert value(body) == 1


def test_scoped_deny_does_not_stop_the_walk():
    guest_deny = rule("deny", "any", "Any", src="VLAN(20).*")
    body = workflow([{"rules": [guest_deny, DEFAULT]}])
    assert value(body) == 1


class Poisoned(dict):
    def __init__(self):
        super().__init__(poisoned=True)

    def boom(self, *args, **kwargs):
        raise RuntimeError("poisoned read")

    get = __getitem__ = __contains__ = keys = items = values = __iter__ = boom

    def __len__(self):
        return 1


def test_except_path_is_not_evaluated():
    out = run(Poisoned())
    assert out["transformedResponse"][KEY] is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"


def test_key_is_new_and_no_existing_transform_emits_it():
    seen = []
    for dirpath, dirnames, filenames in os.walk(os.path.join(ROOT, "safeguards")):
        for fn in filenames:
            path = os.path.join(dirpath, fn)
            if not fn.endswith(".py") or fn.startswith("test_") or path == FILE:
                continue
            with open(path, encoding="utf-8", errors="replace") as fh:
                if '"' + KEY + '"' in fh.read():
                    seen.append(path)
    assert seen == []
