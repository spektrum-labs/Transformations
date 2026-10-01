"""Salesforce Security Health Check transforms: real values on complete query results, None otherwise."""
import importlib.util
import os

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name):
    spec = importlib.util.spec_from_file_location("sf_" + name, os.path.join(HERE, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def query(sobject, records, done=True, total=None):
    recs = [dict(r, attributes={"type": sobject}) for r in records]
    inner = {"size": len(recs), "totalSize": len(recs) if total is None else total, "done": done, "records": recs}
    return {"data": {"apiResponse": inner}, "validation": {"status": "skipped", "errors": [], "warnings": []}}


def value(key, payload):
    return load(key)(payload)["transformedResponse"][key]


def test_score():
    assert value("securityHealthCheckScore", query("SecurityHealthCheck", [{"Score": "85"}])) == 85.0
    assert value("securityHealthCheckScore", query("SecurityHealthCheck", [{"Score": 42}])) == 42.0
    assert value("securityHealthCheckScore", query("SecurityHealthCheck", [{"Score": None}])) is None
    assert value("securityHealthCheckScore", query("SecurityHealthCheck", [])) is None


def test_high_risk_count():
    risks = [{"RiskType": "HIGH_RISK", "Setting": "Minimum password length"}, {"RiskType": "HIGH_RISK", "Setting": "Session timeout"}]
    assert value("highRiskSecuritySettingsCount", query("SecurityHealthCheckRisks", risks)) == 2
    assert value("highRiskSecuritySettingsCount", query("SecurityHealthCheckRisks", [])) == 0
    mixed = risks + [{"RiskType": "MEETS_STANDARD", "Setting": "x"}]
    assert value("highRiskSecuritySettingsCount", query("SecurityHealthCheckRisks", mixed)) is None


def test_wrong_object_is_not_scored():
    assert value("highRiskSecuritySettingsCount", query("Account", [{"RiskType": "HIGH_RISK"}])) is None


@pytest.mark.parametrize("key,sobject,rec", [("securityHealthCheckScore", "SecurityHealthCheck", {"Score": "90"}),
                                             ("highRiskSecuritySettingsCount", "SecurityHealthCheckRisks", {"RiskType": "HIGH_RISK"})])
def test_partial_read_is_not_scored(key, sobject, rec):
    assert value(key, query(sobject, [rec], done=False)) is None
    assert value(key, query(sobject, [rec], total=5)) is None


NO_EVIDENCE = [
    None, {}, [], "",
    [{"message": "Session expired or invalid", "errorCode": "INVALID_SESSION_ID"}],
    {"error": "invalid_client", "error_description": "invalid client credentials"},
    {"status_code": 401, "message": "Unauthorized"},
    {"data": {"unrelated": 1}, "validation": {"status": "skipped", "errors": [], "warnings": []}},
]


@pytest.mark.parametrize("key", ["securityHealthCheckScore", "highRiskSecuritySettingsCount"])
@pytest.mark.parametrize("payload", NO_EVIDENCE)
def test_no_evidence_is_not_measured(key, payload):
    out = load(key)(payload)
    assert out["transformedResponse"][key] is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"
