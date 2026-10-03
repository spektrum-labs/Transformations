"""Cisco Meraki MX: the four transforms production reads from develop (#668, #670, #679).

Ported to main byte-for-byte. These tests pin the verdicts production gives today:
- isFirewallEnabled / isIDSEnabled / isIPSEnabled: a network the definition hands over as
  {"vendorErrorAsResponse": {...}} (400 "Intrusion detection is not supported by this network")
  is unprotected, not unmeasured.
- isFirewallUpdated: percent of appliance networks on the latest stable MX firmware; no measured
  network is no value (None) with dataCollection "error".
"""
import importlib.util
import os

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name):
    spec = importlib.util.spec_from_file_location("meraki_mx_port_" + name, os.path.join(HERE, name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


FW = load("isFirewallEnabled")
IDS = load("isIDSEnabled")
IPS = load("isIPSEnabled")
UPD = load("isFirewallUpdated")

NETS = [{"id": "N_1", "name": "HQ"}, {"id": "N_2", "name": "Branch"}]
UNSUPPORTED = {"vendorErrorAsResponse": {"status": 400, "errors": ["Intrusion detection is not supported by this network"]}}


def value(out, key):
    return out["transformedResponse"][key]


# ---------------------------------------------------------------- isFirewallEnabled
def test_firewall_enabled_passes_when_every_appliance_detects_or_prevents():
    out = FW.transform({"items": [{"mode": "prevention"}, {"mode": "detection"}]})
    assert value(out, "isFirewallEnabled") is True


def test_firewall_enabled_fails_on_disabled_appliance():
    out = FW.transform({"items": [{"mode": "prevention"}, {"mode": "disabled"}]})
    assert value(out, "isFirewallEnabled") is False


def test_firewall_enabled_counts_unsupported_network_as_unprotected():
    out = FW.transform([{"mode": "prevention"}, UNSUPPORTED])
    assert value(out, "isFirewallEnabled") is False
    assert out["transformedResponse"]["modesSeen"].get("not supported") == 1


def test_firewall_enabled_empty_body_is_not_a_pass():
    assert value(FW.transform({}), "isFirewallEnabled") is False


# ---------------------------------------------------------------- isIDSEnabled / isIPSEnabled
@pytest.mark.parametrize("mod,key,modes,expected", [
    (IDS, "isIDSEnabled", ["prevention", "detection"], True),
    (IDS, "isIDSEnabled", ["prevention", "disabled"], False),
    (IPS, "isIPSEnabled", ["prevention", "prevention"], True),
    (IPS, "isIPSEnabled", ["prevention", "detection"], False),
])
def test_intrusion_mode_verdicts(mod, key, modes, expected):
    out = mod.transform({"networks": NETS, "items": [{"mode": m} for m in modes]})
    assert value(out, key) is expected


@pytest.mark.parametrize("mod,key", [(IDS, "isIDSEnabled"), (IPS, "isIPSEnabled")])
def test_intrusion_unsupported_network_fails(mod, key):
    out = mod.transform({"networks": NETS, "items": [{"mode": "prevention"}, UNSUPPORTED]})
    assert value(out, key) is False
    assert out["transformedResponse"]["networksFailing"] == [{"network": "Branch", "mode": "not supported"}]


@pytest.mark.parametrize("mod,key", [(IDS, "isIDSEnabled"), (IPS, "isIPSEnabled")])
def test_intrusion_unreachable_body_is_not_a_pass(mod, key):
    out = mod.transform({"unrelated": True})
    assert value(out, key) is False
    assert out["transformedResponse"]["endpointReached"] is False


@pytest.mark.parametrize("mod,key", [(IDS, "isIDSEnabled"), (IPS, "isIPSEnabled")])
def test_intrusion_unreadable_network_blocks_a_pass(mod, key):
    out = mod.transform({"networks": NETS, "items": [{"mode": "prevention"}, {"noMode": 1}]})
    assert value(out, key) is False
    assert out["transformedResponse"]["networksNotMeasured"] == ["Branch"]


# ---------------------------------------------------------------- isFirewallUpdated
def firmware(current_id, current_date, available):
    return {"products": {"appliance": {
        "currentVersion": {"id": current_id, "shortName": "MX " + str(current_id), "releaseDate": current_date},
        "availableVersions": available,
    }}}


def test_firmware_all_current_is_100():
    body = {"networks": NETS, "items": [firmware(1, "2026-08-01T00:00:00Z", []), firmware(2, "2026-08-01T00:00:00Z", [])]}
    assert value(UPD.transform(body), "isFirewallUpdated") == 100.0


def test_firmware_one_behind_is_50():
    newer = [{"id": 9, "releaseType": "stable", "shortName": "MX 19.1", "releaseDate": "2026-09-01T00:00:00Z"}]
    body = {"networks": NETS, "items": [firmware(1, "2026-08-01T00:00:00Z", []), firmware(2, "2026-08-01T00:00:00Z", newer)]}
    out = UPD.transform(body)
    assert value(out, "isFirewallUpdated") == 50.0
    assert out["transformedResponse"]["networksBehind"][0]["network"] == "Branch"


def test_firmware_older_or_beta_versions_are_not_upgrades():
    available = [
        {"id": 7, "releaseType": "stable", "releaseDate": "2026-01-01T00:00:00Z"},
        {"id": 8, "releaseType": "beta", "releaseDate": "2026-12-01T00:00:00Z"},
    ]
    body = {"networks": NETS[:1], "items": [firmware(1, "2026-08-01T00:00:00Z", available)]}
    assert value(UPD.transform(body), "isFirewallUpdated") == 100.0


def test_firmware_nothing_measured_is_no_value():
    out = UPD.transform({"networks": NETS, "items": [{"products": {}}, {}]})
    assert value(out, "isFirewallUpdated") is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"


def test_firmware_unrelated_body_is_no_value():
    out = UPD.transform({"unrelated": True})
    assert value(out, "isFirewallUpdated") is None
    assert out["transformedResponse"]["endpointReached"] is False
