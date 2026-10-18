"""Cisco Meraki MX follow-up to #1133: the real VPN status shape, a peer list that is not a list, and a
vlansEnabled that arrives as text.

* getOrganizationApplianceVpnStatuses documents a BARE JSON array of per-network objects (the
  response schema is an array; the sample starts with "[{networkId ..."). Both VPN checks must read
  that shape as well as the same list under apiResponse or data.
* A network whose merakiVpnPeers or thirdPartyVpnPeers is present but not a list cannot be counted:
  the check answers None with a dataCollection error and never raises.
* networkSegmentationActive reads vlansEnabled as a boolean; the text "false" is a flat network, not
  a segmented one. A value that is neither boolean nor true/false text is unreadable.

Synthetic data only.
"""
import importlib.util
import json
import os

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name):
    spec = importlib.util.spec_from_file_location("meraki_follow_up_" + name, os.path.join(HERE, name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


PERCENT = load("vpnPeerReachablePercentage")
TUNNEL = load("vpnTunnelEstablished")
SEGMENT = load("networkSegmentationActive")


def value(out, key):
    return out["transformedResponse"][key]


def collection(out):
    return out["additionalInfo"]["dataCollection"]


def up(name="Remote"):
    return {"networkId": "N_2", "networkName": name, "reachability": "reachable"}


def down(name="Remote"):
    return {"networkId": "N_2", "networkName": name, "reachability": "unreachable"}


def third(state="reachable"):
    return {"name": "Peer", "publicIp": "203.0.113.7", "reachability": state}


def network(meraki=None, third_party=None, name="Main", **extra):
    out = {"networkId": "N_1", "networkName": name, "deviceSerial": "Q000-0000-0000", "deviceStatus": "online",
           "vpnMode": "hub", "uplinks": [{"interface": "wan1", "publicIp": "203.0.113.1"}]}
    if meraki is not None:
        out["merakiVpnPeers"] = meraki
    if third_party is not None:
        out["thirdPartyVpnPeers"] = third_party
    out.update(extra)
    return out


# --------------------------------------------- the documented shape: a bare array
def test_documented_bare_array_is_read_by_both_vpn_checks():
    body = [network([up()], [third()])]
    assert value(PERCENT.transform(body), "vpnPeerReachablePercentage") == 100.0
    assert value(TUNNEL.transform(body), "vpnTunnelEstablished") is True
    assert collection(PERCENT.transform(body))["status"] == "success"


def test_documented_bare_array_with_an_unreachable_peer():
    body = [network([up(), down()], [third()])]
    assert value(PERCENT.transform(body), "vpnPeerReachablePercentage") == 66.67
    assert value(TUNNEL.transform(body), "vpnTunnelEstablished") is True
    none_up = [network([down()], [third("unreachable")])]
    assert value(PERCENT.transform(none_up), "vpnPeerReachablePercentage") == 0.0
    assert value(TUNNEL.transform(none_up), "vpnTunnelEstablished") is False


@pytest.mark.parametrize("wrap", [lambda b: {"apiResponse": b}, lambda b: {"data": b}, lambda b: b])
def test_every_delivery_of_the_same_list_gives_the_same_answer(wrap):
    body = [network([up(), down()], [third()])]
    assert value(PERCENT.transform(wrap(body)), "vpnPeerReachablePercentage") == 66.67
    assert value(TUNNEL.transform(wrap(body)), "vpnTunnelEstablished") is True


def test_a_network_with_no_peers_configured_keeps_its_answer():
    body = [network([], [])]
    assert value(PERCENT.transform(body), "vpnPeerReachablePercentage") == 0.0
    assert value(TUNNEL.transform(body), "vpnTunnelEstablished") is False
    assert collection(TUNNEL.transform(body))["status"] == "success"


# --------------------------------------------- a peer list that is not a list
NOT_A_LIST = [5, True, "reachable", {"a": 1}, 1.5]


@pytest.mark.parametrize("bad", NOT_A_LIST)
@pytest.mark.parametrize("field", ["merakiVpnPeers", "thirdPartyVpnPeers"])
def test_a_peer_list_that_is_not_a_list_is_not_evaluated_and_never_raises(field, bad):
    net = network([up()], [third()])
    net[field] = bad
    for mod, key in ((PERCENT, "vpnPeerReachablePercentage"), (TUNNEL, "vpnTunnelEstablished")):
        out = mod.transform([net])
        if key == "vpnTunnelEstablished":
            # the other list still proves a reachable peer
            assert value(out, key) is True
            continue
        assert value(out, key) is None
        assert collection(out)["status"] == "error" and collection(out)["errors"]


@pytest.mark.parametrize("bad", NOT_A_LIST)
def test_tunnel_is_not_evaluated_when_no_reachable_peer_was_read_and_a_list_is_unreadable(bad):
    nets = [network(bad, [third("unreachable")]), network([down()], None, name="Other")]
    out = TUNNEL.transform(nets)
    assert value(out, "vpnTunnelEstablished") is None
    assert collection(out)["status"] == "error" and collection(out)["errors"]
    no_peers = TUNNEL.transform([network(bad, None)])
    assert value(no_peers, "vpnTunnelEstablished") is None


def test_a_reachable_peer_elsewhere_still_proves_the_tunnel():
    nets = [network(5, None, name="Broken"), network([up()], None, name="Good")]
    assert value(TUNNEL.transform(nets), "vpnTunnelEstablished") is True
    assert value(PERCENT.transform(nets), "vpnPeerReachablePercentage") is None


@pytest.mark.parametrize("net", [
    {"networkId": 123, "merakiVpnPeers": 5},
    dict(network(5, None), networkId=123, networkName=None),
])
def test_a_numeric_network_id_next_to_an_unreadable_list_is_not_evaluated_and_never_raises(net):
    for mod, key in ((PERCENT, "vpnPeerReachablePercentage"), (TUNNEL, "vpnTunnelEstablished")):
        for body in ([net], {"data": [net]}):
            out = mod.transform(body)
            assert value(out, key) is None
            assert collection(out)["status"] == "error" and collection(out)["errors"]


def test_the_unreadable_peer_list_reason_is_fixed_text():
    secret = "SECRET-VENDOR-VALUE-123"
    net = network(secret, None)
    for mod, key in ((PERCENT, "vpnPeerReachablePercentage"), (TUNNEL, "vpnTunnelEstablished")):
        text = json.dumps(mod.transform([net]), default=str)
        assert secret not in text
        assert "TypeError" not in text and "not iterable" not in text


def test_absent_or_null_peer_lists_are_no_peers_not_unreadable():
    for net in (network(None, None), dict(network(None, None), merakiVpnPeers=None, thirdPartyVpnPeers=None)):
        assert value(PERCENT.transform([net]), "vpnPeerReachablePercentage") == 0.0
        assert collection(PERCENT.transform([net]))["status"] == "success"


# --------------------------------------------- vlansEnabled as text
def vlans(*flags):
    return {"networks": [{"id": "N_%d" % i, "name": "Net %d" % i} for i in range(len(flags))],
            "vlanSettings": [{"vlansEnabled": f} for f in flags]}


@pytest.mark.parametrize("flat", ["false", "False", "FALSE", " false ", False, 0])
def test_a_flat_network_is_a_fail_whatever_form_the_flag_takes(flat):
    out = SEGMENT.transform(vlans(flat))
    assert value(out, "networkSegmentationActive") is False
    assert out["transformedResponse"]["flatNetworks"] == ["Net 0"]


@pytest.mark.parametrize("on", ["true", "True", "TRUE", " true ", True, 1])
def test_a_segmented_network_is_a_pass_whatever_form_the_flag_takes(on):
    assert value(SEGMENT.transform(vlans(on, True)), "networkSegmentationActive") is True


@pytest.mark.parametrize("junk", ["maybe", "", "  ", "yes", "0", [], {}, [True], 2, 1.5])
def test_a_flag_that_is_neither_boolean_nor_true_false_text_is_unreadable(junk):
    alone = SEGMENT.transform(vlans(junk))
    assert value(alone, "networkSegmentationActive") is None
    assert collection(alone)["status"] == "error" and collection(alone)["errors"]
    beside_pass = SEGMENT.transform(vlans(True, junk))
    assert value(beside_pass, "networkSegmentationActive") is None          # a pass cannot be proven
    beside_fail = SEGMENT.transform(vlans("false", junk))
    assert value(beside_fail, "networkSegmentationActive") is False          # the fail was read
