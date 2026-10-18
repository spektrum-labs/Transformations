"""Halcyon (Endpoint Security): fail-closed checks over checkInstalled (GET /search/devices/metrics).

Bodies are SYNTHETIC: Halcyon's public OpenAPI (api.halcyon.ai/docs) names the three fields of
GET /search/devices/metrics (DeviceMetrics: total, no_heartbeats, need_updates, all required int32) but
not what an error or refused body looks like, so the error shapes here are the ones Integration-Service
hands over (a statusCode or error flag, optionally wrapped, as a dict or a JSON string). No customer data.

Rules under test (both keys): an error, 401/403, empty, unrecognised, incomplete or incoherent body, and
a tenant with no registered devices, is Not evaluated: the value is null and
additionalInfo.dataCollection.status is "error". Never 0, never False.
"""
import copy
import importlib.util
import json
import pathlib

import pytest

HERE = pathlib.Path(__file__).resolve().parent
KEYS = {"offlineSensorCount": "no_heartbeats", "sensorOutOfDateCount": "need_updates"}


def load(name):
    spec = importlib.util.spec_from_file_location("halcyon_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def result(name, body):
    return load(name).transform(copy.deepcopy(body))


def value(name, body):
    return result(name, body)["transformedResponse"][name]


def metrics(total=10, no_heartbeats=0, need_updates=0):
    return {"total": total, "no_heartbeats": no_heartbeats, "need_updates": need_updates}


def not_evaluated(name, body):
    out = result(name, body)
    assert out["transformedResponse"] == {name: None}
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"
    assert out["additionalInfo"]["dataCollection"]["errors"]
    return out


@pytest.mark.parametrize("name,field", list(KEYS.items()))
def test_counts_the_vendor_field_for_its_own_key(name, field):
    body = metrics(total=40, no_heartbeats=3, need_updates=7)
    assert value(name, body) == body[field]


@pytest.mark.parametrize("name", list(KEYS))
def test_zero_is_a_pass_with_a_pass_reason(name):
    out = result(name, metrics(total=25))
    assert out["transformedResponse"] == {name: 0}
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"
    assert out["additionalInfo"]["evaluation"]["passReasons"]
    assert out["additionalInfo"]["evaluation"]["failReasons"] == []


@pytest.mark.parametrize("name", list(KEYS))
def test_a_positive_count_is_a_fail_reason_not_an_error(name):
    out = result(name, metrics(total=25, no_heartbeats=2, need_updates=2))
    assert out["transformedResponse"][name] == 2
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"
    assert out["additionalInfo"]["evaluation"]["failReasons"]
    assert out["additionalInfo"]["evaluation"]["recommendations"]


def test_the_two_keys_do_not_read_each_others_field():
    body = metrics(total=30, no_heartbeats=0, need_updates=9)
    assert value("offlineSensorCount", body) == 0
    assert value("sensorOutOfDateCount", body) == 9


def test_every_device_without_a_heartbeat_is_counted_not_capped():
    assert value("offlineSensorCount", metrics(total=5, no_heartbeats=5)) == 5


@pytest.mark.parametrize("name", list(KEYS))
def test_only_the_key_is_returned_so_no_second_criterion_leaks(name):
    out = result(name, metrics(total=8, no_heartbeats=1, need_updates=1))
    assert list(out["transformedResponse"]) == [name]


@pytest.mark.parametrize("name", list(KEYS))
@pytest.mark.parametrize("wrap", [
    lambda m: m,
    lambda m: {"apiResponse": m},
    lambda m: {"status": 200, "apiResponse": m},
    lambda m: {"apiResponse": {"data": m}},
    lambda m: {"apiResponse": json.dumps(m)},
    lambda m: {"response": {"result": m}},
    lambda m: json.dumps(m),
    lambda m: json.dumps({"apiResponse": m}),
])
def test_the_body_is_found_under_any_wrapper(name, wrap):
    assert value(name, wrap(metrics(total=12, no_heartbeats=4, need_updates=6))) == (4 if name == "offlineSensorCount" else 6)


@pytest.mark.parametrize("name", list(KEYS))
@pytest.mark.parametrize("body", [
    {},
    None,
    "",
    "{}",
    "[]",
    "not json at all",
    [],
    [metrics()],
    {"apiResponse": {}},
    {"apiResponse": "{}"},
    {"apiResponse": None},
    {"unrelated": [1, 2, 3], "items": []},
    {"message": "Something went wrong"},
    {"detail": "Forbidden"},
    {"apiResponse": {"message": "Forbidden"}},
])
def test_an_empty_or_unrecognised_body_is_not_evaluated(name, body):
    not_evaluated(name, body)


@pytest.mark.parametrize("name", list(KEYS))
@pytest.mark.parametrize("body", [
    {"error": True, "statusCode": 401, "message": "Unauthorized"},
    {"error": True, "statusCode": 403, "message": "Forbidden"},
    {"statusCode": 403, "message": "Forbidden"},
    {"statusCode": 404, "message": "Not Found"},
    {"statusCode": 500, "message": "Internal Server Error"},
    {"errorType": "AuthError", "message": "bad token"},
    {"status": 401, "apiResponse": {"message": "Unauthorized"}},
    {"status": False, "message": "refused"},
    {"apiResponse": {"statusCode": 403, "message": "Forbidden"}},
    {"apiResponse": json.dumps({"error": True, "statusCode": 401, "message": "Unauthorized"})},
    {"apiResponse": {"error": True, "statusCode": 429, "message": "Too Many Requests"}},
])
def test_an_error_or_refused_answer_is_not_evaluated(name, body):
    not_evaluated(name, body)


@pytest.mark.parametrize("name", list(KEYS))
def test_an_error_next_to_metrics_is_still_an_error(name):
    body = {"statusCode": 403, "message": "Forbidden"}
    body.update(metrics(total=10, no_heartbeats=0, need_updates=0))
    not_evaluated(name, body)


@pytest.mark.parametrize("name", list(KEYS))
@pytest.mark.parametrize("missing", ["total", "no_heartbeats", "need_updates"])
def test_a_body_missing_any_field_is_not_evaluated(name, missing):
    body = metrics(total=10, no_heartbeats=1, need_updates=1)
    del body[missing]
    not_evaluated(name, body)


@pytest.mark.parametrize("name", list(KEYS))
@pytest.mark.parametrize("bad", ["3", None, True, False, 2.5, -1, [], {}])
@pytest.mark.parametrize("field", ["total", "no_heartbeats", "need_updates"])
def test_a_field_that_is_not_a_whole_number_is_not_evaluated(name, field, bad):
    body = metrics(total=10, no_heartbeats=1, need_updates=1)
    body[field] = bad
    not_evaluated(name, body)


@pytest.mark.parametrize("name", list(KEYS))
def test_a_tenant_with_no_devices_is_not_evaluated_not_a_pass(name):
    not_evaluated(name, metrics(total=0, no_heartbeats=0, need_updates=0))


@pytest.mark.parametrize("name", list(KEYS))
@pytest.mark.parametrize("body", [
    metrics(total=5, no_heartbeats=6, need_updates=0),
    metrics(total=5, no_heartbeats=0, need_updates=6),
])
def test_a_count_larger_than_total_is_not_evaluated(name, body):
    not_evaluated(name, body)


@pytest.mark.parametrize("name", list(KEYS))
def test_a_value_is_never_false_or_a_bare_zero_when_nothing_was_measured(name):
    for body in ({}, None, "", {"statusCode": 403}, metrics(total=0)):
        got = result(name, body)["transformedResponse"][name]
        assert got is None


@pytest.mark.parametrize("name", list(KEYS))
def test_the_transform_does_not_mutate_its_input(name):
    body = {"apiResponse": metrics(total=9, no_heartbeats=2, need_updates=1)}
    snapshot = copy.deepcopy(body)
    load(name).transform(body)
    assert body == snapshot
