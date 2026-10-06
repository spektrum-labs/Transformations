"""FortiGate permissiveOutboundRuleCount (NSF-003): fixtures follow the FortiOS REST cmdb body shape
({"http_method", "results", "vdom", "status", "http_status"}) for firewall/policy, system/interface, system/zone and
system/sdwan, merged by the getOutboundPolicyEvidence workflow, with each part as Integration-Service returns it
(returnSpec fields beside apiResponse). Interface, zone and policy names are synthetic. Cases run typed,
stringified (as Token-Service stores it), wrapped, and through the RestrictedPython replica."""
import importlib.util
import json
import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
FILE = os.path.join(HERE, "permissiveoutboundrulecount.py")
KEY = "permissiveOutboundRuleCount"


def load_plain():
    spec = importlib.util.spec_from_file_location("fortigate_permissive_outbound", FILE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def load_sandboxed():
    pytest.importorskip("RestrictedPython")
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import restricted_sandbox
    with open(FILE) as fh:
        return restricted_sandbox.load(fh.read())["transform"]


def fortios(results, path="firewall", name="policy", status="success", http_status=200):
    return {"http_method": "GET", "results": results, "vdom": "root", "path": path, "name": name,
            "status": status, "http_status": http_status, "serial": "FGVMTEST00000000", "version": "v7.4.3",
            "build": 2573}


def is_part(body, extra=None):
    """How Integration-Service returns a method result: returnSpec fields beside the raw body."""
    out = {"apiResponse": body}
    if extra:
        out.update(extra)
    return out


def ref(*names):
    return [{"name": n, "q_origin_key": n} for n in names]


def policy(pid, src, dst, service=("ALL",), dstaddr=("all",), action="accept", status="enable", name=None):
    return {"policyid": pid, "name": name or "p%d" % pid, "srcintf": ref(*src), "dstintf": ref(*dst),
            "srcaddr": ref("all"), "dstaddr": ref(*dstaddr), "service": ref(*service), "action": action,
            "status": status, "schedule": "always", "internet-service": "disable"}


INTERFACES = fortios([
    {"name": "wan1", "role": "wan", "type": "physical"},
    {"name": "wan2", "role": "wan", "type": "physical"},
    {"name": "internal", "role": "lan", "type": "hard-switch"},
    {"name": "guest", "role": "lan", "type": "vlan"},
    {"name": "dmz", "role": "dmz", "type": "physical"},
], "system", "interface")
ZONES = fortios([{"name": "users-zone", "interface": [{"interface-name": "internal"}, {"interface-name": "guest"}]}],
                "system", "zone")
SDWAN = fortios({"status": "enable", "zone": ref("virtual-wan-link", "underlay"),
                 "members": [{"interface": "wan1", "zone": "virtual-wan-link"}]}, "system", "sdwan")


def workflow(policies, interfaces=INTERFACES, zones=ZONES, sdwan=SDWAN):
    return {
        "firewallPolicies": is_part(policies, {"policies": policies.get("results", []) if isinstance(policies, dict) else []}),
        "systemInterfaces": is_part(interfaces),
        "systemZones": is_part(zones),
        "sdwan": is_part(sdwan),
    }


PASSING = workflow(fortios([
    policy(1, ["internal"], ["wan1"], service=("HTTP", "HTTPS", "DNS")),
    policy(2, ["guest"], ["virtual-wan-link"], service=("HTTPS",)),
    policy(3, ["internal"], ["dmz"]),                                 # internal-to-DMZ: not outbound
    policy(4, ["internal"], ["wan1"], dstaddr=("203.0.113.10",)),       # a named destination
    policy(5, ["internal"], ["wan2"], status="disable"),               # disabled
]))
FAILING = workflow(fortios([
    policy(1, ["internal"], ["wan1"], service=("HTTP", "HTTPS")),
    policy(7, ["users-zone"], ["virtual-wan-link"], name="users out"),
    policy(9, ["guest"], ["any"], name="guest any"),
]))


def stringify(value):
    if isinstance(value, dict):
        return {k: stringify(v) for k, v in value.items()}
    if isinstance(value, list):
        return [stringify(v) for v in value]
    return str(value)


def ts_wrap(body):
    return {"data": {"apiResponse": body}, "validation": {"status": "skipped", "errors": [], "warnings": []}}


def value(body, transform=None):
    return (transform or load_plain())(body)["transformedResponse"][KEY]


@pytest.mark.parametrize("form", ["typed", "stringified", "wrapped", "json-string"])
@pytest.mark.parametrize("loader", ["plain", "sandboxed"])
def test_pass_and_fail(form, loader):
    transform = load_plain() if loader == "plain" else load_sandboxed()
    good, bad = PASSING, FAILING
    if form == "stringified":
        good, bad = stringify(good), stringify(bad)
    if form == "wrapped":
        good, bad = ts_wrap(good), ts_wrap(bad)
    if form == "json-string":
        good, bad = json.dumps(good), json.dumps(bad)
    out_good = transform(good)
    assert out_good["transformedResponse"][KEY] == 0
    assert out_good["additionalInfo"]["dataCollection"]["status"] == "success"
    assert "VDOM root" in out_good["additionalInfo"]["evaluation"]["passReasons"][0]
    out_bad = transform(bad)
    assert out_bad["transformedResponse"][KEY] == 2
    reason = out_bad["additionalInfo"]["evaluation"]["failReasons"][0]
    assert "policy 7 'users out'" in reason and "policy 9 'guest any'" in reason


NO_EVIDENCE = [
    {}, None, "", "{}", "not json",
    {"error": {"type": "authentication_error", "message": "invalid credentials"}},
    {"statusCode": 401, "error": "Unauthorized"},
    {"status_code": 401, "error": "Unauthorized"},
    {"error": {"statusCode": 401, "message": "Unauthorized"}},
    {"statusCode": 403, "error": "Forbidden"},
    {"hello": "world"},
    {"foo": {"bar": [1, 2, 3]}},
    # getFirewallPolicies' returnSpec defaults "policies" to [] when the call fails: never evidence
    {"policies": [], "apiResponse": {"http_method": "GET", "status": "error", "http_status": 401}},
    {"firewallPolicies": {"policies": []}},
]


@pytest.mark.parametrize("body", NO_EVIDENCE)
def test_no_evidence_is_not_evaluated(body):
    for wrapped in (body, ts_wrap(body)):
        out = load_plain()(wrapped)
        assert out["transformedResponse"][KEY] is None
        assert out["additionalInfo"]["dataCollection"]["status"] == "error"
        assert out["additionalInfo"]["dataCollection"]["errors"]


def test_failed_or_missing_parts_are_not_evaluated():
    denied = {"http_method": "GET", "status": "error", "http_status": 403, "vdom": "root"}
    policies = fortios([policy(7, ["internal"], ["wan1"])])
    assert value(workflow(policies, interfaces=denied)) is None
    assert value(workflow(policies, zones=denied)) is None
    assert value(workflow(fortios([], status="error", http_status=500))) is None
    body = workflow(policies)
    del body["systemInterfaces"]
    assert value(body) is None
    body = workflow(policies)
    body["firewallPolicies"] = {"error": True, "message": "HTTP 401 Unauthorized"}
    assert value(body) is None


def test_an_empty_policy_list_is_not_evaluated():
    assert value(workflow(fortios([]))) is None


def test_sdwan_is_optional_but_unknown_destinations_are_not_guessed():
    missing = {"http_method": "GET", "status": "error", "http_status": 404}
    # without the SD-WAN read, virtual-wan-link is still internet-facing by name
    assert value(workflow(fortios([policy(7, ["internal"], ["virtual-wan-link"])]), sdwan=missing)) == 1
    # an SD-WAN zone that only the SD-WAN read names cannot be resolved without it
    assert value(workflow(fortios([policy(7, ["internal"], ["underlay"])]), sdwan=missing)) is None
    assert value(workflow(fortios([policy(7, ["internal"], ["underlay"])]))) == 1


def test_unresolved_destination_interface_is_not_evaluated():
    assert value(workflow(fortios([policy(8, ["internal"], ["port9"])]))) is None


def test_zone_with_a_wan_member_is_internet_facing():
    zones = fortios([{"name": "uplinks", "interface": [{"interface-name": "wan2"}]}], "system", "zone")
    assert value(workflow(fortios([policy(8, ["internal"], ["uplinks"])]), zones=zones)) == 1


def test_internet_service_and_wan_to_wan_are_not_counted():
    p = policy(8, ["internal"], ["wan1"])
    p["internet-service"] = "enable"
    assert value(workflow(fortios([p, policy(9, ["wan1"], ["wan2"])]))) == 0


class Poisoned(dict):
    def __init__(self):
        super().__init__(poisoned=True)

    def boom(self, *args, **kwargs):
        raise RuntimeError("poisoned read")

    get = __getitem__ = __contains__ = keys = items = values = __iter__ = boom

    def __len__(self):
        return 1


def test_except_path_is_not_evaluated():
    out = load_plain()(Poisoned())
    assert out["transformedResponse"][KEY] is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"


def test_key_is_new_and_no_existing_transform_emits_it():
    seen = []
    for dirpath, dirnames, filenames in os.walk(os.path.join(ROOT, "safeguards")):
        for fn in filenames:
            path = os.path.join(dirpath, fn)
            if not fn.endswith(".py") or fn.startswith("test_") or os.path.basename(path) == os.path.basename(FILE):
                continue
            with open(path, encoding="utf-8", errors="replace") as fh:
                if '"' + KEY + '"' in fh.read():
                    seen.append(path)
    assert seen == []


def test_ipv6_any_destination_counts():
    p = policy(11, ["internal"], ["wan1"], dstaddr=())
    p["dstaddr6"] = ref("all")
    assert value(workflow(fortios([p]))) == 1


def test_negated_fields_do_not_match():
    p = policy(12, ["internal"], ["wan1"])
    p["dstaddr-negate"] = "enable"
    q = policy(13, ["internal"], ["wan1"])
    q["service-negate"] = "enable"
    assert value(workflow(fortios([p, q]))) == 0


def test_a_confirmed_failure_is_not_hidden_by_an_unresolved_policy():
    out = load_plain()(workflow(fortios([policy(7, ["internal"], ["wan1"]), policy(8, ["internal"], ["port9"])])))
    assert out["transformedResponse"][KEY] == 1
    assert "port9" in out["additionalInfo"]["evaluation"]["failReasons"][0]


def test_a_paged_or_partial_read_is_not_evaluated():
    body = fortios([policy(1, ["internal"], ["wan1"], service=("HTTPS",))])
    body["next_idx"] = 50
    assert value(workflow(body)) is None
    body = fortios([policy(1, ["internal"], ["wan1"], service=("HTTPS",))])
    body["matched_count"] = 9
    assert value(workflow(body)) is None


def test_an_inbound_policy_to_an_unknown_interface_does_not_grey_the_read():
    assert value(workflow(fortios([policy(1, ["wan1"], ["port9"]), policy(2, ["internal"], ["wan1"], service=("HTTPS",))]))) == 0
