"""Sophos isTamperProtectionEnabled reads tamperProtectionEnabled from the endpoints list (2026-10-06).

Fixtures follow the documented Sophos Central shape for GET /endpoint/v1/endpoints. Hostnames
and ids are synthetic.
"""
import importlib.util
import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest

HERE = Path(__file__).parent
KEY = "isTamperProtectionEnabled"


def load():
    spec = importlib.util.spec_from_file_location("sophos_tamper", HERE / "istamperprotectionenabled.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


MOD = load()
NOW = datetime.utcnow()


def seen(days_ago=0):
    return (NOW - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def endpoint(n, enabled=True, supported=True, days_ago=0, drop=False):
    e = {
        "id": "e0000000-0000-4000-8000-%012d" % n,
        "type": "computer",
        "hostname": "host-%02d" % n,
        "lastSeenAt": seen(days_ago),
        "assignedProducts": [{"code": "endpointProtection", "version": "2026.2.1", "status": "installed"}],
        "tamperProtectionEnabled": enabled,
        "tamperProtectionSupported": supported,
    }
    if drop:
        del e["tamperProtectionEnabled"]
        del e["tamperProtectionSupported"]
    return e


def body(*items):
    return {"items": list(items), "pages": {"fromKey": None, "nextKey": None, "size": 500, "maxSize": 500}}


def run(payload):
    out = MOD.transform(payload)
    return out["transformedResponse"][KEY], out


def collection_status(out):
    return out["additionalInfo"]["dataCollection"]["status"]


def test_all_active_endpoints_on_passes():
    value, out = run(body(endpoint(1), endpoint(2), endpoint(3)))
    assert value is True
    assert out["transformedResponse"]["tamperProtectedEndpoints"] == 3
    assert out["transformedResponse"]["tamperProtectedPercentage"] == 100


def test_one_endpoint_off_fails_and_names_it():
    value, out = run(body(endpoint(1), endpoint(2, enabled=False)))
    assert value is False
    tr = out["transformedResponse"]
    assert tr["tamperProtectionOffEndpoints"] == 1
    assert tr["endpointsWithTamperProtectionOff"] == ["host-02"]
    assert tr["tamperProtectedPercentage"] == 50


def test_unsupported_endpoint_is_excluded_and_named():
    value, out = run(body(endpoint(1), endpoint(2, enabled=False, supported=False)))
    assert value is True
    tr = out["transformedResponse"]
    assert tr["unsupportedEndpointsExcluded"] == 1
    assert tr["endpointsWithoutTamperSupport"] == ["host-02"]
    assert tr["judgedEndpoints"] == 1
    assert any("host-02" in f for f in out["additionalInfo"]["evaluation"]["additionalFindings"])


def test_unsupported_reporting_enabled_is_not_counted_as_protected():
    # Linux servers report enabled true together with supported false.
    value, out = run(body(endpoint(1, enabled=False), endpoint(2, enabled=True, supported=False)))
    assert value is False
    tr = out["transformedResponse"]
    assert tr["tamperProtectedEndpoints"] == 0
    assert tr["unsupportedEndpointsExcluded"] == 1


def test_supported_off_still_fails_beside_unsupported():
    value, out = run(body(endpoint(1, enabled=False), endpoint(2, enabled=False, supported=False)))
    assert value is False
    assert out["transformedResponse"]["endpointsWithTamperProtectionOff"] == ["host-01"]


def test_every_active_endpoint_unsupported_is_not_evaluated():
    value, out = run(body(endpoint(1, enabled=True, supported=False), endpoint(2, enabled=False, supported=False)))
    assert value is None
    assert collection_status(out) == "error"
    assert out["transformedResponse"]["unsupportedEndpointsExcluded"] == 2


def test_stale_endpoint_off_is_excluded():
    value, out = run(body(endpoint(1), endpoint(2, enabled=False, days_ago=40)))
    assert value is True
    assert out["transformedResponse"]["staleEndpointsExcluded"] == 1


@pytest.mark.parametrize("payload", [{}, None, "{}", {"items": []}, body(), {"hello": "world"},
                                     {"error": True, "errorMessage": "401 Unauthorized"}])
def test_empty_or_unrecognised_is_not_evaluated(payload):
    value, out = run(payload)
    assert value is None
    assert collection_status(out) == "error"


def test_field_missing_everywhere_is_not_evaluated():
    value, out = run(body(endpoint(1, drop=True), endpoint(2, drop=True)))
    assert value is None
    assert collection_status(out) == "error"


def test_field_missing_on_some_with_rest_on_is_not_evaluated():
    value, out = run(body(endpoint(1), endpoint(2, drop=True)))
    assert value is None
    assert out["transformedResponse"]["endpointsWithoutTamperData"] == 1


def test_off_beats_missing_data():
    value, _ = run(body(endpoint(1, enabled=False), endpoint(2, drop=True)))
    assert value is False


def test_dark_fleet_is_not_evaluated():
    value, out = run(body(endpoint(1, days_ago=60), endpoint(2, days_ago=61)))
    assert value is None
    assert out["transformedResponse"]["staleEndpointsExcluded"] == 2


def test_string_booleans_from_stored_replays():
    e = endpoint(1)
    e["tamperProtectionEnabled"] = "true"
    e["tamperProtectionSupported"] = "true"
    assert run(body(e))[0] is True
    e["tamperProtectionEnabled"] = "false"
    assert run(body(e))[0] is False


def test_truthy_non_boolean_is_not_evidence():
    e = endpoint(1)
    e["tamperProtectionEnabled"] = 1
    assert run(body(e))[0] is None


def test_platform_wrappers_and_json_string():
    wrapped = {"result": {"apiResponse": {"result": body(endpoint(1))}}}
    assert run(wrapped)[0] is True
    assert run(json.dumps(body(endpoint(1))))[0] is True
    assert run(body(endpoint(1))["items"])[0] is True


def test_unread_next_page_is_not_evaluated():
    payload = body(endpoint(1), endpoint(2))
    payload["pages"]["nextKey"] = "eyJwYWdlIjoyfQ"
    value, out = run(payload)
    assert value is None
    assert collection_status(out) == "error"


def test_page_total_above_one_with_one_page_is_not_evaluated():
    payload = body(endpoint(1))
    payload["pages"] = {"current": 1, "size": 50, "total": 3, "maxSize": 500}
    assert run(payload)[0] is None


def test_full_first_page_without_cursor_is_not_evaluated():
    payload = body(*[endpoint(n) for n in range(1, 4)])
    payload["pages"] = {"size": 3, "maxSize": 500}
    assert run(payload)[0] is None


@pytest.mark.parametrize("flag_value", [True, "true"])
def test_truncated_list_is_not_evaluated(flag_value):
    payload = body(endpoint(1), endpoint(2))
    payload["pages"]["truncated"] = flag_value
    value, out = run(payload)
    assert value is None
    assert collection_status(out) == "error"


def test_stored_replay_pages_are_read_as_complete():
    payload = body(endpoint(1))
    payload["pages"] = {"size": "500", "maxSize": "500", "nextKey": "None"}
    assert run(payload)[0] is True


def test_stored_replay_string_page_total_is_not_evaluated():
    payload = body(endpoint(1))
    payload["pages"] = {"current": "1", "size": "50", "total": "3", "nextKey": "None"}
    assert run(payload)[0] is None


def test_merged_list_with_null_cursor_passes():
    payload = body(*[endpoint(n) for n in range(1, 4)])
    payload["pages"] = {"size": 3, "maxSize": 500, "nextKey": None}
    assert run(payload)[0] is True


def test_exception_path_is_not_evaluated():
    value, out = run(b"\xff not json")
    assert value is None
    assert collection_status(out) == "error"
