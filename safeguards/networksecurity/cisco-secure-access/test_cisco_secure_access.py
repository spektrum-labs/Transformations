"""Cisco Secure Access hasNetworkTunnelsConfigured: real verdicts on complete reads, None otherwise."""
import importlib.util
import os

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
KEY = "hasNetworkTunnelsConfigured"


def load():
    spec = importlib.util.spec_from_file_location("cisco_sa_tunnels", os.path.join(HERE, KEY + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def group(i, status):
    return {"id": i, "name": "ntg-" + str(i), "status": status, "hubs": []}


def body(groups, total=None, wrap=True):
    page = {"data": groups, "offset": 0, "limit": 200, "total": len(groups) if total is None else total}
    if not wrap:
        return page
    return {"data": page, "validation": {"status": "skipped", "errors": [], "warnings": []}}


def out(payload):
    return load()(payload)["transformedResponse"]


def test_connected_group_is_configured():
    r = out(body([group(1, "connected"), group(2, "disconnected")]))
    assert r[KEY] is True
    assert r["connectedTunnelGroups"] == 1
    assert r["disconnectedTunnelGroups"] == 1
    assert r["connectedTunnelGroupPercentage"] == 50.0


def test_warning_counts_as_live_but_not_connected():
    r = out(body([group(1, "warning")], wrap=False))
    assert r[KEY] is True
    assert r["connectedTunnelGroupPercentage"] == 0.0


def test_all_disconnected_or_empty_is_false():
    assert out(body([group(1, "disconnected")]))[KEY] is False
    assert out(body([]))[KEY] is False


def test_partial_read_is_not_scored():
    assert out(body([group(1, "connected")], total=300))[KEY] is None


def test_group_without_status_is_not_scored():
    assert out(body([{"id": 1, "name": "x"}]))[KEY] is None


NO_EVIDENCE = [
    None,
    {},
    [],
    "",
    {"error": True, "message": "Unauthorized", "status_code": 401},
    {"message": "Forbidden", "statusCode": 403},
    {"data": {"unrelated": 1}, "validation": {"status": "skipped", "errors": [], "warnings": []}},
    {"data": [group(1, "connected")]},
]


@pytest.mark.parametrize("payload", NO_EVIDENCE)
def test_no_evidence_is_not_measured(payload):
    result = load()(payload)
    assert result["transformedResponse"][KEY] is None
    assert result["additionalInfo"]["dataCollection"]["status"] == "error"
