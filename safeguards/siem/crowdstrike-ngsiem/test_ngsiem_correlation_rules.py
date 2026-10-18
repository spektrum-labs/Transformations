"""CrowdStrike NG-SIEM correlation-rule checks on the MSA body of combined_rules_get_v1 filtered to
status:'active'. No customer body has been seen."""
import importlib.util
import pathlib

import pytest

HERE = pathlib.Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location("ngs_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def msa(statuses, total=None):
    rules = [{"id": str(i), "name": "r%d" % i, "status": s} for i, s in enumerate(statuses)]
    return {"meta": {"pagination": {"offset": 0, "limit": 500, "total": len(rules) if total is None else total}}, "resources": rules, "errors": []}


FAIL_CLOSED = [{}, None, "{}", "", {"error": True, "statusCode": 401}, {"hello": "world"},
               {"meta": {}, "resources": [], "errors": [{"code": 403, "message": "access denied, authorization failed"}]},
               msa(["active", "inactive"]), msa(["active"], total=0)]


@pytest.mark.parametrize("body", FAIL_CLOSED)
def test_fail_closed(body):
    assert load("ispolicyenabled")(body)["isPolicyEnabled"] is False
    assert load("activecorrelationrulescount")(body)["activeCorrelationRulesCount"] is None


def test_pass_and_flip():
    assert load("ispolicyenabled")(msa(["active"] * 3, total=620))["isPolicyEnabled"] is True
    assert load("activecorrelationrulescount")({"apiResponse": msa(["active"] * 3, total=620)})["activeCorrelationRulesCount"] == 620
    assert load("ispolicyenabled")(msa([]))["isPolicyEnabled"] is False
    assert load("activecorrelationrulescount")(msa([]))["activeCorrelationRulesCount"] == 0
