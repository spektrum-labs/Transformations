"""isControllerOnline: True only when every enabled controller reports online; one offline panel is always False; anything unreadable is None."""
import importlib.util
import json
import os

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
KEY = "isControllerOnline"


def load():
    spec = importlib.util.spec_from_file_location("acre_controller_online", os.path.join(HERE, KEY + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def controller(i, online=True, disabled=False, status=True):
    c = {"CommonName": "Panel " + str(i), "Key": "ctl-" + str(i), "IsDisabled": disabled}
    if status:
        c["Status"] = {"IsOnline": online}
    return c


def body(items, truncated=False):
    inner = {"controllers": items}
    if truncated:
        inner["paginationTruncated"] = True
    return {"data": {"apiResponse": inner}, "validation": {"status": "skipped", "errors": [], "warnings": []}}


def run(payload):
    return load()(payload)


def value(payload):
    return run(payload)["transformedResponse"][KEY]


def not_evaluated(payload):
    out = run(payload)
    return out["transformedResponse"][KEY] is None and out["additionalInfo"]["dataCollection"]["status"] == "error"


def test_all_enabled_controllers_online():
    out = run(body([controller(1), controller(2), controller(3, online=False, disabled=True)]))
    assert out["transformedResponse"][KEY] is True
    assert out["transformedResponse"]["enabledControllerCount"] == 2
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"


def test_one_offline_enabled_controller_is_false_and_named():
    out = run(body([controller(1), controller(2, online=False)]))
    assert out["transformedResponse"][KEY] is False
    assert out["transformedResponse"]["offlineControllers"] == ["Panel 2"]


def test_flipping_one_controller_flips_the_answer():
    assert value(body([controller(1, True)])) is True
    assert value(body([controller(1, False)])) is False


def test_an_offline_controller_is_false_even_when_another_is_unreadable():
    assert value(body([controller(1, online=False), controller(2, status=False)])) is False


def test_an_unreadable_controller_hides_a_true():
    assert not_evaluated(body([controller(1), controller(2, status=False)]))
    payload = body([controller(1)])
    payload["data"]["apiResponse"]["controllers"].append({"CommonName": "odd", "Status": {"IsOnline": "yes"}})
    assert not_evaluated(payload)


def test_no_enabled_controller_is_not_measured():
    assert not_evaluated(body([]))
    assert not_evaluated(body([controller(1, disabled=True)]))


def test_partial_read_is_not_scored_even_with_an_offline_panel():
    assert not_evaluated(body([controller(1, online=False)], truncated=True))


def test_camel_case_projection_is_read():
    assert value(body([{"commonName": "P", "isDisabled": False, "status": {"isOnline": False}}])) is False


def test_bare_list_and_string_inputs_are_read():
    items = [controller(1), controller(2, online=False)]
    assert value(items) is False
    assert value(json.dumps({"controllers": items})) is False


NO_EVIDENCE = [
    None, {}, [], "", "{}",
    {"errors": ["Unauthorized"]},
    {"error": "invalid_client", "status_code": 400},
    {"statusCode": 403, "error": "Forbidden"},
    {"data": {"apiResponse": {"Message": "denied", "error": True}}, "validation": {}},
    {"data": {"apiResponse": {"status_code": 500, "message": "boom"}}, "validation": {}},
    {"data": {"unrelated": 1}, "validation": {"status": "skipped", "errors": [], "warnings": []}},
    {"controllers": ["a", "b"]},
    {"controllers": [1, 2]},
]


@pytest.mark.parametrize("payload", NO_EVIDENCE)
def test_no_evidence_is_not_measured(payload):
    assert not_evaluated(payload)


def test_an_offline_controller_name_is_bounded_before_it_reaches_the_stream():
    c = controller(1, online=False)
    c["CommonName"] = "P" * 5000
    names = run(body([c]))["transformedResponse"]["offlineControllers"]
    assert len(names) == 1 and len(names[0]) <= 80
