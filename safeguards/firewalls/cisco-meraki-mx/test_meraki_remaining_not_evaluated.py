"""Cisco Meraki MX firewall, VPN and login-policy checks: a body that proves nothing is Not evaluated.

Token-Service grades a None criterion as FAILED unless additionalInfo.dataCollection.status is
"error", so every check below must answer None AND carry a dataCollection error when the body is
empty, a vendor error (403, 429, 5xx, timeout text) or is not the shape the check reads. A false is
only returned from a body that was read and shows the control missing. A fan-out check (one call per
network) is False when at least one network was read and fails, None when no network could be read or
when the readable networks all pass but some network could not be read (a pass cannot be proven),
and True only when every network was read and passes. Synthetic data only.
"""
import importlib.util
import json
import os

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name):
    spec = importlib.util.spec_from_file_location("meraki_remaining_ne_" + name, os.path.join(HERE, name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


KEYS = [
    "defaultDenyInbound",
    "isApiKeyIpRestrictionEnabled",
    "isContinuousDiscoveryEnabled",
    "isFirewallConfigured",
    "isFirewallEnabled",
    "isFirewallLoggingEnabled",
    "isFirewallUpdated",
    "isIDSEnabled",
    "isIPSEnabled",
    "isNetworkSecurityLoggingEnabled",
    "isProgrammaticAccessEnabled",
    "isStrongPasswordPolicyEnforced",
    "networkSegmentationActive",
    "vpnPeerReachablePercentage",
    "vpnTunnelEstablished",
]
MODS = {key: load(key) for key in KEYS}

ENVELOPE_VALIDATION = {"status": "skipped", "errors": [], "warnings": []}
ERROR_BODIES = [
    {},
    None,
    [],
    "",
    "not json",
    "HTTP 429: Too Many Requests",
    "Read timed out",
    {"error": True, "message": "Integration execution error: HTTP 403: Forbidden"},
    {"errors": ["API key invalid"]},
    {"vendorErrorAsResponse": {"status": 403, "errors": ["Forbidden"]}},
    {"vendorErrorAsResponse": {"status": 429, "errors": ["Too many requests"]}},
    {"vendorErrorAsResponse": {"status": 503, "errors": ["Service unavailable"]}},
    {"data": {"error": True, "message": "HTTP 500"}, "validation": ENVELOPE_VALIDATION},
]
ERR_403 = {"vendorErrorAsResponse": {"status": 403, "errors": ["Forbidden"]}}
ERR_500 = {"vendorErrorAsResponse": {"status": 500, "errors": ["Internal error"]}}
NETS = [{"id": "N_1", "name": "Site A"}, {"id": "N_2", "name": "Site B"}]


def value(out, key):
    return out["transformedResponse"][key]


def collection(out):
    return out["additionalInfo"]["dataCollection"]


def assert_not_evaluated(out, key):
    assert value(out, key) is None
    assert collection(out)["status"] == "error" and collection(out)["errors"]
    assert out["additionalInfo"]["evaluation"]["passReasons"] == []


# ---------------------------------------------------------------- every check, every unusable body
@pytest.mark.parametrize("body", ERROR_BODIES, ids=lambda b: json.dumps(b)[:40])
@pytest.mark.parametrize("key", [k for k in KEYS])
def test_unusable_body_is_not_evaluated(key, body):
    out = MODS[key].transform(body)
    assert_not_evaluated(out, key)


@pytest.mark.parametrize("key", ["isFirewallEnabled", "isFirewallLoggingEnabled"])
def test_unparseable_text_never_echoes_the_exception(key):
    out = MODS[key].transform("not json")
    assert_not_evaluated(out, key)
    assert "Expecting value" not in json.dumps(out["additionalInfo"])


@pytest.mark.parametrize("key", ["isFirewallEnabled", "isFirewallLoggingEnabled"])
def test_failed_input_validation_is_not_evaluated(key):
    out = MODS[key].transform({"data": {"items": [{"mode": "prevention"}]}, "validation": {"status": "failed", "errors": ["x"], "warnings": []}})
    assert_not_evaluated(out, key)


# ---------------------------------------------------------------- fan-out checks (one call per network)
RULES_DENY = {"rules": [
    {"comment": "Block all", "policy": "deny", "srcCidr": "Any", "destCidr": "Any"},
    {"comment": "Default rule", "policy": "allow", "srcCidr": "Any", "destCidr": "Any"},
]}
RULES_PERMIT = {"rules": [
    {"comment": "Allow web", "policy": "allow", "srcCidr": "Any", "destCidr": "Any"},
    {"comment": "Default rule", "policy": "allow", "srcCidr": "Any", "destCidr": "Any"},
]}
RULES_DEFAULT_ONLY = {"rules": [{"comment": "Default rule", "policy": "allow", "srcCidr": "Any", "destCidr": "Any"}]}
SYSLOG_GOOD = {"servers": [{"host": "203.0.113.5", "port": "514", "roles": ["Security events", "IDS alerts"]}]}
SYSLOG_NONE = {"servers": []}

# key, key of the per-network list beside `networks`, passing response, failing response
FANOUT = [
    ("defaultDenyInbound", "l3FirewallRules", RULES_DENY, RULES_PERMIT),
    ("isFirewallConfigured", "l3FirewallRules", RULES_PERMIT, RULES_DEFAULT_ONLY),
    ("isIDSEnabled", "items", {"mode": "prevention"}, {"mode": "disabled"}),
    ("isIPSEnabled", "items", {"mode": "prevention"}, {"mode": "detection"}),
    ("isNetworkSecurityLoggingEnabled", "syslogServers", SYSLOG_GOOD, SYSLOG_NONE),
    ("networkSegmentationActive", "vlanSettings", {"vlansEnabled": True}, {"vlansEnabled": False}),
]
FANOUT_IDS = [row[0] for row in FANOUT]


def fan(row, responses):
    return {"networks": NETS[:len(responses)], row[1]: responses}


@pytest.mark.parametrize("row", FANOUT, ids=FANOUT_IDS)
def test_fanout_every_network_read_and_passing_is_true(row):
    out = MODS[row[0]].transform(fan(row, [row[2], row[2]]))
    assert value(out, row[0]) is True
    assert collection(out)["status"] == "success"


@pytest.mark.parametrize("row", FANOUT, ids=FANOUT_IDS)
def test_fanout_a_read_failing_network_is_false(row):
    out = MODS[row[0]].transform(fan(row, [row[2], row[3]]))
    assert value(out, row[0]) is False
    assert collection(out)["status"] == "success"


@pytest.mark.parametrize("row", FANOUT, ids=FANOUT_IDS)
def test_fanout_failing_network_still_fails_when_another_is_unreadable(row):
    out = MODS[row[0]].transform(fan(row, [row[3], ERR_500]))
    assert value(out, row[0]) is False


@pytest.mark.parametrize("row", FANOUT, ids=FANOUT_IDS)
def test_fanout_unreadable_network_blocks_a_pass(row):
    out = MODS[row[0]].transform(fan(row, [row[2], ERR_500]))
    assert_not_evaluated(out, row[0])


@pytest.mark.parametrize("row", FANOUT, ids=FANOUT_IDS)
def test_fanout_no_network_readable_is_not_evaluated(row):
    for responses in ([ERR_403, ERR_500], [{}, {}], [ERR_403]):
        assert_not_evaluated(MODS[row[0]].transform(fan(row, responses)), row[0])
    assert_not_evaluated(MODS[row[0]].transform([ERR_403, ERR_500]), row[0])


@pytest.mark.parametrize("row", FANOUT, ids=FANOUT_IDS)
def test_fanout_empty_estate_is_not_evaluated(row):
    assert_not_evaluated(MODS[row[0]].transform({"networks": [], row[1]: []}), row[0])
    assert_not_evaluated(MODS[row[0]].transform({"networks": NETS}), row[0])


@pytest.mark.parametrize("key", ["isIDSEnabled", "isIPSEnabled"])
def test_intrusion_only_a_400_means_not_supported(key):
    unsupported = {"vendorErrorAsResponse": {"status": 400, "errors": ["Intrusion detection is not supported by this network"]}}
    body = {"networks": NETS, "items": [{"mode": "prevention"}, unsupported]}
    out = MODS[key].transform(body)
    assert value(out, key) is False
    assert out["transformedResponse"]["networksFailing"] == [{"network": "Site B", "mode": "not supported"}]
    # a 403 or a 5xx is a failed read, not a statement about the network
    body = {"networks": NETS, "items": [{"mode": "prevention"}, ERR_403]}
    assert_not_evaluated(MODS[key].transform(body), key)


# ---------------------------------------------------------------- isFirewallEnabled
def test_firewall_enabled_verdicts():
    fw = MODS["isFirewallEnabled"]
    unsupported = {"vendorErrorAsResponse": {"status": 400, "errors": ["Intrusion detection is not supported by this network"]}}
    assert value(fw.transform({"items": [{"mode": "prevention"}, {"mode": "detection"}]}), "isFirewallEnabled") is True
    assert value(fw.transform({"items": [{"mode": "prevention"}, {"mode": "disabled"}]}), "isFirewallEnabled") is False
    assert value(fw.transform([{"mode": "prevention"}, unsupported]), "isFirewallEnabled") is False
    assert value(fw.transform([{"mode": "disabled"}, ERR_500]), "isFirewallEnabled") is False


def test_firewall_enabled_unreadable_appliance_blocks_a_pass():
    fw = MODS["isFirewallEnabled"]
    assert_not_evaluated(fw.transform([{"mode": "prevention"}, ERR_500]), "isFirewallEnabled")
    assert_not_evaluated(fw.transform({"items": []}), "isFirewallEnabled")
    assert_not_evaluated(fw.transform({"items": [{"unrelated": 1}]}), "isFirewallEnabled")


# ---------------------------------------------------------------- isFirewallLoggingEnabled
def test_firewall_logging_verdicts():
    log = MODS["isFirewallLoggingEnabled"]
    key = "isFirewallLoggingEnabled"
    assert value(log.transform([SYSLOG_GOOD, SYSLOG_GOOD]), key) is True
    assert value(log.transform([SYSLOG_GOOD, SYSLOG_NONE]), key) is False
    assert value(log.transform(SYSLOG_NONE), key) is False
    assert value(log.transform([SYSLOG_NONE, ERR_500]), key) is False
    assert value(log.transform([{"host": "203.0.113.5", "roles": ["Flows"]}]), key) is True


def test_firewall_logging_unreadable_network_blocks_a_pass():
    log = MODS["isFirewallLoggingEnabled"]
    assert_not_evaluated(log.transform([SYSLOG_GOOD, ERR_500]), "isFirewallLoggingEnabled")
    assert_not_evaluated(log.transform([ERR_403, ERR_500]), "isFirewallLoggingEnabled")


# ---------------------------------------------------------------- organization settings checks
def test_api_key_ip_restriction_verdicts():
    mod, key = MODS["isApiKeyIpRestrictionEnabled"], "isApiKeyIpRestrictionEnabled"
    restricted = {"apiAuthentication": {"ipRestrictionsForKeys": {"enabled": True, "ranges": ["203.0.113.0/24"]}}}
    open_keys = {"apiAuthentication": {"ipRestrictionsForKeys": {"enabled": False}}}
    assert value(mod.transform(restricted), key) is True
    assert value(mod.transform(open_keys), key) is False
    for body in ({"apiAuthentication": {}}, {"apiAuthentication": {"ipRestrictionsForKeys": {}}},
                 {"apiAuthentication": {"ipRestrictionsForKeys": {"enabled": None}}}, {"id": "1", "name": "Org"}):
        assert_not_evaluated(mod.transform(body), key)


def test_programmatic_access_verdicts():
    mod, key = MODS["isProgrammaticAccessEnabled"], "isProgrammaticAccessEnabled"
    assert value(mod.transform({"id": "1", "name": "Org", "api": {"enabled": True}}), key) is True
    assert value(mod.transform({"id": "1", "name": "Org", "api": {"enabled": False}}), key) is False
    for body in ({"id": "1", "name": "Org"}, {"api": {}}, {"api": {"enabled": None}}):
        assert_not_evaluated(mod.transform(body), key)


def test_strong_password_policy_verdicts():
    mod, key = MODS["isStrongPasswordPolicyEnforced"], "isStrongPasswordPolicyEnforced"
    assert value(mod.transform({"enforceStrongPasswords": True, "minimumPasswordLength": 12}), key) is True
    assert value(mod.transform({"enforceStrongPasswords": True}), key) is True
    assert value(mod.transform({"enforceStrongPasswords": True, "minimumPasswordLength": 6}), key) is False
    assert value(mod.transform({"enforceStrongPasswords": False, "minimumPasswordLength": 12}), key) is False
    for body in ({"minimumPasswordLength": 12}, {"enforceStrongPasswords": None}, {"enforceStrongPasswords": "yes"}):
        assert_not_evaluated(mod.transform(body), key)


def test_continuous_discovery_verdicts():
    mod, key = MODS["isContinuousDiscoveryEnabled"], "isContinuousDiscoveryEnabled"
    devices = [{"serial": "Q2XX-AAAA-0001", "productType": "appliance"}, {"serial": "Q2XX-AAAA-0002", "productType": "switch"}]
    assert value(mod.transform(devices), key) is True
    assert value(mod.transform({"items": devices}), key) is True
    for body in ([], {"items": []}, [ERR_403], [{"unrelated": 1}]):
        assert_not_evaluated(mod.transform(body), key)


# ---------------------------------------------------------------- VPN checks
def vpn_body(*peers):
    return {"apiResponse": [{
        "networkId": "N_1", "networkName": "Site A",
        "merakiVpnPeers": list(peers), "thirdPartyVpnPeers": [],
    }]}


UP = {"networkId": "N_2", "networkName": "Site B", "reachability": "reachable"}
DOWN = {"networkId": "N_3", "networkName": "Site C", "reachability": "unreachable"}


def test_vpn_peer_reachable_percentage_verdicts():
    mod, key = MODS["vpnPeerReachablePercentage"], "vpnPeerReachablePercentage"
    assert value(mod.transform(vpn_body(UP, UP)), key) == 100.0
    assert value(mod.transform(vpn_body(UP, DOWN)), key) == 50.0
    assert value(mod.transform(vpn_body(DOWN)), key) == 0.0
    assert value(mod.transform(vpn_body()), key) == 0.0          # networks read, no peers configured
    assert value(mod.transform([vpn_body(UP)["apiResponse"][0]]), key) == 100.0
    for body in ({"apiResponse": []}, {"apiResponse": [ERR_403]}, {"apiResponse": "x"}):
        assert_not_evaluated(mod.transform(body), key)


def test_vpn_tunnel_established_verdicts():
    mod, key = MODS["vpnTunnelEstablished"], "vpnTunnelEstablished"
    assert value(mod.transform(vpn_body(UP, DOWN)), key) is True
    assert value(mod.transform(vpn_body(DOWN)), key) is False
    assert value(mod.transform(vpn_body()), key) is False       # networks read, no peers configured
    assert value(mod.transform([vpn_body(UP)["apiResponse"][0]]), key) is True
    for body in ({"apiResponse": []}, {"apiResponse": [ERR_403]}, {"apiResponse": "x"}):
        assert_not_evaluated(mod.transform(body), key)


# ---------------------------------------------------------------- isFirewallUpdated is already correct
def test_firmware_unreadable_is_not_evaluated():
    mod, key = MODS["isFirewallUpdated"], "isFirewallUpdated"
    assert_not_evaluated(mod.transform({"networks": NETS, "items": [ERR_403, ERR_500]}), key)
