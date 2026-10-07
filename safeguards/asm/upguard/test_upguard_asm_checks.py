"""UpGuard (Attack Surface Management) checks on bodies shaped like the public API spec
(cyber-risk.upguard.com/api/swagger.json). No customer body has been seen."""
import importlib.util
import pathlib

import pytest

HERE = pathlib.Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location("ug_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


FAIL_CLOSED = [{}, None, "{}", "", {"error": True, "statusCode": 401}, {"hello": "world"}]


@pytest.mark.parametrize("body", FAIL_CLOSED)
def test_fail_closed(body):
    assert load("nocriticalfindings")(body)["noCriticalFindings"] is False
    assert load("nohighfindings")(body)["noHighFindings"] is False
    assert load("isasmenabled")(body)["isASMEnabled"] is False
    assert load("exploitedfindingscount")(body)["exploitedFindingsCount"] is None


def test_severity_checks():
    high_only = {"risks": [{"id": "r1", "severity": "high"}]}
    assert load("nocriticalfindings")(high_only)["noCriticalFindings"] is True
    assert load("nohighfindings")(high_only)["noHighFindings"] is False
    crit = {"apiResponse": {"risks": [{"id": "r2", "severity": "critical"}]}}
    assert load("nocriticalfindings")(crit)["noCriticalFindings"] is False
    assert load("nohighfindings")(crit)["noHighFindings"] is True
    assert load("nocriticalfindings")({"risks": []})["noCriticalFindings"] is True
    assert load("nocriticalfindings")({"risks": [{"severity": "severe"}]})["noCriticalFindings"] is False


def test_asm_enabled():
    t = load("isasmenabled")
    assert t({"domains": [{"hostname": "a.example", "active": True, "scanned_at": "2026-09-20T00:00:00Z"}]})["isASMEnabled"] is True
    assert t({"domains": [{"hostname": "a.example", "active": True}]})["isASMEnabled"] is False
    assert t({"domains": []})["isASMEnabled"] is False


def test_exploited_count():
    t = load("exploitedfindingscount")
    body = {"vulnerabilities": [{"hostname": "a", "known_exploited_vulnerability": True},
                                {"hostname": "b", "known_exploited_vulnerability": False}]}
    assert t(body)["exploitedFindingsCount"] == 1
    assert t({"vulnerabilities": []})["exploitedFindingsCount"] == 0
    assert t({"vulnerabilities": [{"hostname": "a"}]})["exploitedFindingsCount"] is None
