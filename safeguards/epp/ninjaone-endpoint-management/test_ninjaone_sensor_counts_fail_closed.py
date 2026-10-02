"""offlineSensorCount, staleSensorCount and endpointOperationalStatusUnprotectedCount fail closed (2 Oct 2026).

The core-key live verification found all three returned 0 (a pass on "count == 0") from an empty vendor
reply. An empty, missing or error reply now reads None with the reason in dataCollection.errors
(Unevaluated); a real device list still measures.

Samples follow NinjaOne's documented shapes (GET /v2/devices-detailed returns a bare list of device objects
with id, systemName, nodeClass, offline and lastContact in epoch seconds; GET
/v2/queries/antivirus-status returns {"results": [{deviceId, productName, productState, timestamp}],
"cursor": ...}). Raw vendor bodies are not readable from the evidence store (403), so these are the
documented shapes, not captured bodies.
"""
import importlib.util
import json
import pathlib
import time

import pytest

HERE = pathlib.Path(__file__).parent


def load(name):
    spec = importlib.util.spec_from_file_location("n1fc_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


KEYS = {
    "offlineSensorCount": "offlineSensorCount",
    "staleSensorCount": "staleSensorCount",
    "endpointOperationalStatusUnprotectedCount": "endpointOperationalStatusUnprotectedCount",
}

EMPTY_OR_ERROR = [
    {},
    [],
    None,
    "",
    "{}",
    "not json",
    b"[]",
    {"data": []},
    {"value": []},
    {"items": []},
    {"results": []},
    {"resources": []},
    {"data": [], "validation": {"status": "unknown", "errors": [], "warnings": []}},
    {"data": {}, "validation": {"status": "failed", "errors": ["schema"], "warnings": []}},
    {"error": "invalid_token", "error_description": "Access token expired"},
    {"statusCode": 401, "message": "Unauthorized"},
    {"apiResponse": {"error": "Forbidden"}},
    [1, "x", None],
]


@pytest.mark.parametrize("name", list(KEYS))
@pytest.mark.parametrize("body", EMPTY_OR_ERROR, ids=lambda b: json.dumps(b, default=str)[:40])
def test_empty_missing_or_error_reply_is_unevaluated_with_a_reason(name, body):
    out = load(name)(body)
    assert out["transformedResponse"][KEYS[name]] is None
    collection = out["additionalInfo"]["dataCollection"]
    assert collection["status"] == "error"
    assert collection["errors"] and all(isinstance(e, str) and e for e in collection["errors"])


NOW = time.time()


def devices():
    return [
        {"id": 1, "systemName": "WS-01", "nodeClass": "WINDOWS_WORKSTATION", "offline": False, "lastContact": NOW - 60},
        {"id": 2, "systemName": "WS-02", "nodeClass": "WINDOWS_WORKSTATION", "offline": True, "lastContact": NOW - 20 * 86400},
        {"id": 3, "systemName": "SRV-01", "nodeClass": "WINDOWS_SERVER", "offline": False, "lastContact": NOW - 3600},
    ]


def test_offline_measures_a_real_device_list():
    out = load("offlineSensorCount")(devices())
    assert out["transformedResponse"]["offlineSensorCount"] == 1
    assert out["transformedResponse"]["totalDevices"] == 3
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"


def test_offline_measures_a_real_zero():
    body = [dict(d, offline=False) for d in devices()]
    out = load("offlineSensorCount")({"data": body, "validation": {"status": "valid", "errors": [], "warnings": []}})
    assert out["transformedResponse"]["offlineSensorCount"] == 0
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"


def test_offline_unreadable_flag_is_unevaluated():
    body = [{"id": 1, "systemName": "WS-01"}]
    assert load("offlineSensorCount")(body)["transformedResponse"]["offlineSensorCount"] is None


def test_stale_measures_a_real_device_list():
    out = load("staleSensorCount")(json.dumps(devices()))
    assert out["transformedResponse"]["staleSensorCount"] == 1
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"


def test_stale_measures_a_real_zero():
    body = [dict(d, lastContact=NOW - 60) for d in devices()]
    out = load("staleSensorCount")(body)
    assert out["transformedResponse"]["staleSensorCount"] == 0
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"


def test_stale_without_any_last_contact_is_unevaluated():
    body = [{"id": 1, "systemName": "WS-01", "offline": False}]
    assert load("staleSensorCount")(body)["transformedResponse"]["staleSensorCount"] is None


def av_report(rows):
    return {"results": rows, "cursor": {"name": "c1", "offset": 0, "count": len(rows), "expires": 0}}


def test_unprotected_measures_a_real_report():
    rows = [
        {"deviceId": 1, "productName": "Windows Defender", "productState": "ON", "timestamp": NOW - 60},
        {"deviceId": 3, "productName": "Windows Defender", "productState": "OFF", "timestamp": NOW - 60},
    ]
    out = load("endpointOperationalStatusUnprotectedCount")(av_report(rows))
    assert out["transformedResponse"]["endpointOperationalStatusUnprotectedCount"] == 1
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"


def test_unprotected_measures_a_real_zero():
    rows = [{"deviceId": 1, "productName": "Windows Defender", "productState": "ON", "timestamp": NOW - 60}]
    out = load("endpointOperationalStatusUnprotectedCount")(av_report(rows))
    assert out["transformedResponse"]["endpointOperationalStatusUnprotectedCount"] == 0
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"


def test_unprotected_rows_without_device_ids_are_unevaluated():
    out = load("endpointOperationalStatusUnprotectedCount")(av_report([{"productState": "ON"}]))
    assert out["transformedResponse"]["endpointOperationalStatusUnprotectedCount"] is None
