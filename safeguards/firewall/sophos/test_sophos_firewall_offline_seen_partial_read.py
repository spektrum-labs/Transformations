"""Sophos Firewall isFirewallEnabled: an offline firewall that was seen is a proven failure even when the list was not
read whole or another firewall's status is unreadable. The control is "every firewall is connected", so one counted
firewall with status.connected false fails it however many others were not read. Anything that shows no offline
firewall and is not a whole read stays Not evaluated (None with a dataCollection error). Fixtures follow the documented
GET /firewall/v1/firewalls body (items[].status.connected, items[].cluster {mode, status}, pages {current, size,
total, nextKey}); identifiers are synthetic."""
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
    spec = importlib.util.spec_from_file_location("sophos_isfirewallenabled_seen_offline", FILE)
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
    fw = {"id": "00000000-0000-4000-8000-%012d" % i,
          "status": {"managingStatus": "approvedByCustomer", "connected": connected, "suspended": False}}
    if cluster:
        fw["cluster"] = {"mode": cluster[0], "status": cluster[1]}
    return fw


def unreadable(i):
    """A firewall whose status carries no connected field at all."""
    return {"id": "00000000-0000-4000-8000-%012d" % i, "status": {"managingStatus": "approvedByCustomer"}}


def page(items, size=1000, **pages):
    return {"items": items, "pages": dict({"current": 1, "size": size, "maxSize": 1000}, **pages)}


def stringify(value):
    if isinstance(value, dict):
        return {k: stringify(v) for k, v in value.items()}
    if isinstance(value, list):
        return [stringify(v) for v in value]
    return str(value)


def ts_wrap(body):
    return {"data": {"apiResponse": body}, "validation": {"status": "skipped", "errors": [], "warnings": []}}


FORMS = {"typed": lambda b: b, "stringified": stringify, "wrapped": ts_wrap, "json-string": json.dumps}


def run(body, loader):
    transform = load_plain() if loader == "plain" else load_sandboxed()
    return transform(body)


def verdict(out):
    return out["transformedResponse"][KEY], out["additionalInfo"]["dataCollection"]["status"]


# A negative proven by a firewall that was seen: False, whatever was not read.
SEEN_OFFLINE_NOT_WHOLE = {
    "page 1 of 2": page([firewall(0), firewall(1, connected=False)], total=2),
    "next key": page([firewall(0, connected=False)], nextKey="49bbba02"),
    "full page, no total": page([firewall(0), firewall(1, connected=False)], size=2),
    "one unreadable beside an offline one": page([unreadable(0), firewall(1, connected=False)], total=1),
    "partial and one unreadable": page([unreadable(0), firewall(1, connected=False)], total=2),
    "offline primary beside a standby": page([firewall(0, connected=False, cluster=("activePassive", "primary")),
                                              firewall(1, cluster=("activePassive", "auxiliary"))], total=3),
}


@pytest.mark.parametrize("form", sorted(FORMS))
@pytest.mark.parametrize("loader", ["plain", "sandboxed"])
@pytest.mark.parametrize("name", sorted(SEEN_OFFLINE_NOT_WHOLE))
def test_a_seen_offline_firewall_fails_even_when_not_every_firewall_was_read(name, loader, form):
    out = run(FORMS[form](SEEN_OFFLINE_NOT_WHOLE[name]), loader)
    assert verdict(out) == (False, "success")
    assert out["additionalInfo"]["dataCollection"]["errors"] == []


@pytest.mark.parametrize("name", sorted(SEEN_OFFLINE_NOT_WHOLE))
def test_counts_are_none_when_the_read_was_not_whole(name):
    out = run(SEEN_OFFLINE_NOT_WHOLE[name], "plain")
    assert out["transformedResponse"]["totalFirewalls"] is None
    assert out["transformedResponse"]["connectedFirewalls"] is None
    assert "not read whole" in out["additionalInfo"]["evaluation"]["failReasons"][0]


def test_a_whole_read_still_reports_its_counts():
    body = page([firewall(0), firewall(1, connected=False), firewall(2, connected=False)], total=1)
    out = run(body, "plain")
    assert verdict(out) == (False, "success")
    assert out["transformedResponse"]["totalFirewalls"] == 3
    assert out["transformedResponse"]["connectedFirewalls"] == 1
    assert "2 of 3" in out["additionalInfo"]["evaluation"]["failReasons"][0]


# Nothing seen offline and not a whole read: no evidence, so Not evaluated, never False.
NO_OFFLINE_SEEN = {
    "page 1 of 2, all seen connected": page([firewall(0), firewall(1)], total=2),
    "next key, all seen connected": page([firewall(0)], nextKey="49bbba02"),
    "full page, no total, all connected": page([firewall(0), firewall(1)], size=2),
    "unreadable beside a connected one": page([firewall(0), unreadable(1)], total=1),
    "every firewall unreadable": page([unreadable(0), unreadable(1)], total=1),
    "connected null": page([firewall(0), firewall(1, connected=None)], total=1),
    "partial, only a standby offline": page([firewall(0, cluster=("activePassive", "primary")),
                                             firewall(1, connected=False, cluster=("activePassive", "auxiliary"))],
                                            total=2),
    "empty list": page([]),
    "empty list, partial": page([], total=2),
    "error body": {"error": "Unauthorized", "message": "Authentication required"},
    "vendor error": {"vendorErrorAsResponse": True, "statusCode": 403},
    "empty": {},
    "none": None,
    "not json": "not json",
}


@pytest.mark.parametrize("loader", ["plain", "sandboxed"])
@pytest.mark.parametrize("name", sorted(NO_OFFLINE_SEEN))
def test_no_offline_firewall_seen_and_not_a_whole_read_is_not_evaluated(name, loader):
    body = NO_OFFLINE_SEEN[name]
    for shaped in (body, ts_wrap(body)):
        out = run(shaped, loader)
        assert verdict(out) == (None, "error")
        assert out["additionalInfo"]["dataCollection"]["errors"]


def test_failed_validation_is_still_not_evaluated():
    body = {"data": page([firewall(0, connected=False)], total=2),
            "validation": {"status": "failed", "errors": ["401"], "warnings": []}}
    assert verdict(run(body, "plain")) == (None, "error")


def test_a_whole_read_with_every_firewall_connected_still_passes():
    body = page([firewall(i) for i in range(3)], total=1)
    assert verdict(run(body, "plain")) == (True, "success")
