"""Sophos Firewall isFirewallEnabled: fixtures follow the documented GET /firewall/v1/firewalls response
(https://developer.sophos.com/reference/firewall-v1/firewalls/list-firewalls/, items[].status.connected boolean,
items[].cluster {mode, status}, pages {current, size, maxSize, total?}). Identifiers are synthetic and no hostname,
serial or address is carried. Every case runs typed, stringified (as Token-Service stores it), Token-Service-wrapped,
as a JSON string, and through the RestrictedPython replica."""
import importlib.util
import json
import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
FILE = os.path.join(HERE, "isfirewallenabled.py")
KEY = "isFirewallEnabled"


def load_plain():
    spec = importlib.util.spec_from_file_location("sophos_isfirewallenabled", FILE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def load_sandboxed():
    pytest.importorskip("RestrictedPython")
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import restricted_sandbox
    with open(FILE) as fh:
        return restricted_sandbox.load(fh.read())["transform"]


def firewall(i, connected=True, cluster=None):
    fw = {"id": "00000000-0000-4000-8000-%012d" % i, "tenant": {"id": "00000000-0000-4000-8000-000000000000"},
          "firmwareVersion": "SF01V_SO01_21.0.0", "externalIpv4Addresses": [],
          "status": {"managingStatus": "approvedByCustomer", "reportingStatus": "approvedByCustomer",
                     "connected": connected, "suspended": False}}
    if cluster:
        fw["cluster"] = {"id": "00000000-0000-4000-9000-000000000001", "mode": cluster[0], "status": cluster[1],
                         "peers": []}
    return fw


def page(items, size=1000, **pages):
    return {"items": items, "pages": dict({"current": 1, "size": size, "maxSize": 1000}, **pages)}


ALL_CONNECTED = page([firewall(i) for i in range(3)])
ONE_OF_FIFTY = page([firewall(0)] + [firewall(i, connected=False) for i in range(1, 50)])
EMPTY = page([])


def stringify(value):
    if isinstance(value, dict):
        return {k: stringify(v) for k, v in value.items()}
    if isinstance(value, list):
        return [stringify(v) for v in value]
    return str(value)


def ts_wrap(body):
    return {"data": {"apiResponse": body}, "validation": {"status": "skipped", "errors": [], "warnings": []}}


FORMS = {"typed": lambda b: b, "stringified": stringify, "wrapped": ts_wrap, "json-string": json.dumps}


def outcome(body, transform):
    out = transform(body)
    return out["transformedResponse"][KEY], out["additionalInfo"]["dataCollection"]["status"]


@pytest.mark.parametrize("form", sorted(FORMS))
@pytest.mark.parametrize("loader", ["plain", "sandboxed"])
def test_three_replays(form, loader):
    transform = load_plain() if loader == "plain" else load_sandboxed()
    shape = FORMS[form]
    assert outcome(shape(ALL_CONNECTED), transform) == (True, "success")
    assert outcome(shape(ONE_OF_FIFTY), transform) == (False, "success")
    assert outcome(shape(EMPTY), transform) == (None, "error")


def test_fail_reason_counts_the_offline_firewalls():
    out = load_plain()(ONE_OF_FIFTY)
    assert "49 of 50" in out["additionalInfo"]["evaluation"]["failReasons"][0]
    assert out["transformedResponse"]["connectedFirewalls"] == 1


def test_documented_example_body_passes():
    # The 200 example on the vendor page, reduced to the fields read: one connected firewall that is the primary of
    # an active-active cluster, with the example's own "managing"/"reporting" spellings.
    body = {"items": [{"id": "39df20ba-7330-41ae-9071-0ac682bdd1e6",
                       "cluster": {"id": "6a72014b-ae91-4d50-807a-d3601e44b9b7", "mode": "activeActive",
                                   "status": "primary"},
                       "status": {"managing": "approvalPending", "reporting": "approvalPending",
                                  "connected": True, "suspended": False}}],
            "pages": {"current": 1, "total": 1, "items": 1, "size": 100, "maxSize": 1000}}
    assert outcome(body, load_plain()) == (True, "success")


def test_standby_member_of_active_passive_pair_is_not_counted():
    body = page([firewall(0, cluster=("activePassive", "primary")),
                 firewall(1, connected=False, cluster=("activePassive", "auxiliary"))])
    assert outcome(body, load_plain()) == (True, "success")


def test_active_active_auxiliary_is_counted():
    body = page([firewall(0, cluster=("activeActive", "primary")),
                 firewall(1, connected=False, cluster=("activeActive", "auxiliary"))])
    assert outcome(body, load_plain()) == (False, "success")


def test_disconnected_primary_fails_even_with_a_connected_standby():
    body = page([firewall(0, connected=False, cluster=("activePassive", "primary")),
                 firewall(1, cluster=("activePassive", "auxiliary"))])
    assert outcome(body, load_plain()) == (False, "success")


def renamed(body):
    out = json.loads(json.dumps(body))
    for fw in out["items"]:
        fw["status"]["isConnected"] = fw["status"].pop("connected")
    return out


class Poisoned(dict):
    def __getitem__(self, key):
        raise RuntimeError("poisoned")

    get = __getitem__

    def __contains__(self, key):
        raise RuntimeError("poisoned")


NO_EVIDENCE = {
    "empty list": EMPTY,
    "renamed status.connected": renamed(ALL_CONNECTED),
    "connected null": page([firewall(0), firewall(1, connected=None)]),
    "no items array": {"pages": {"current": 1, "size": 1000, "maxSize": 1000}},
    "error body": {"error": "Unauthorized", "message": "Authentication required"},
    "vendor error": {"vendorErrorAsResponse": True, "statusCode": 403},
    "page 1 of 2": page([firewall(0)], total=2),
    "next key": page([firewall(0)], nextKey="49bbba02"),
    "full page, no total": page([firewall(i) for i in range(5)], size=5),
    "not a dict": [firewall(0)],
    "empty": {},
    "none": None,
    "not json": "not json",
}


@pytest.mark.parametrize("name", sorted(NO_EVIDENCE))
@pytest.mark.parametrize("loader", ["plain", "sandboxed"])
def test_no_evidence_is_not_evaluated(name, loader):
    transform = load_plain() if loader == "plain" else load_sandboxed()
    body = NO_EVIDENCE[name]
    for shaped in (body, ts_wrap(body)):
        assert outcome(shaped, transform) == (None, "error")


def test_failed_validation_is_not_evaluated():
    body = {"data": ALL_CONNECTED, "validation": {"status": "failed", "errors": ["401"], "warnings": []}}
    assert outcome(body, load_plain()) == (None, "error")


@pytest.mark.parametrize("loader", ["plain", "sandboxed"])
def test_poisoned_body_is_not_evaluated(loader):
    transform = load_plain() if loader == "plain" else load_sandboxed()
    assert outcome(Poisoned(), transform) == (None, "error")


def test_full_page_with_a_total_of_one_page_is_whole():
    body = page([firewall(i) for i in range(5)], size=5, total=1)
    assert outcome(body, load_plain()) == (True, "success")
