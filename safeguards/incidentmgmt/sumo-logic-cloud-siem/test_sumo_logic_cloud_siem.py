"""Sumo Logic Cloud SIEM isPolicyEnabled: a real count on a filtered read, None on anything else."""
import importlib.util
import json
import os

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("sumo_cse_isPolicyEnabled", os.path.join(HERE, "isPolicyEnabled.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def rule(i, enabled=True):
    return {"id": "THRESHOLD-S" + str(i), "name": "Rule " + str(i), "enabled": enabled}


def body(objects, total):
    page = {"hasNextPage": total > len(objects), "total": total, "objects": objects}
    return {"data": {"data": page, "apiResponse": {"data": page, "errors": []}},
            "validation": {"status": "skipped", "errors": [], "warnings": []}}


def value(payload):
    return module.transform(payload)["transformedResponse"]["isPolicyEnabled"]


def test_enabled_rules_pass_and_report_the_count():
    out = module.transform(body([rule(1)], 412))["transformedResponse"]
    assert out["isPolicyEnabled"] is True
    assert out["enabledRuleCount"] == 412


def test_real_zero_is_false():
    assert value(body([], 0)) is False


def test_bare_page_and_string_body():
    page = {"hasNextPage": False, "total": 3, "objects": [rule(1)]}
    assert value({"data": page}) is True
    assert value(json.dumps({"data": page})) is True


def test_filter_not_applied_is_not_measured():
    assert value(body([rule(1, enabled=False)], 900)) is None


def test_inconsistent_total_is_not_measured():
    assert value(body([], 5)) is None


@pytest.mark.parametrize("payload", [
    None, {}, [], "", {"data": {}},
    {"errors": [{"code": "unauthorized", "message": "Credential could not be verified."}]},
    {"status": 401, "message": "Unauthorized"},
    {"data": {"total": "many", "objects": []}},
    {"data": {"total": True, "objects": []}},
    {"data": {"objects": [rule(1)]}},
    {"foo": {"bar": 1}},
])
def test_no_evidence_is_none(payload):
    assert value(payload) is None
