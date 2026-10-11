"""Tests for the One-Click Endpoint files added for honest verdicts (2026-09-29)."""
import importlib.util
from pathlib import Path


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SCORE = load("microsoft_endpoint_configurationscore")
SERVER = load("microsoft_endpoint_servercoverage")
EDR = load("microsoft_endpoint_edrdeployed")
SCID = load("microsoft_endpoint_scid_compliance")
NO_EVIDENCE = (None, {}, "", {"error": True, "message": "HTTP 403"}, {"error": {"code": "InvalidAuthenticationToken"}})


def value(module, payload, key):
    return module.transform(payload)["transformedResponse"][key]


def collection_errors(module, payload):
    return module.transform(payload)["additionalInfo"]["dataCollection"]["errors"]


def test_configuration_score_reads_the_score_as_a_percentage():
    body = {"@odata.context": "https://api.securitycenter.microsoft.com/api/$metadata#ConfigurationScore/$entity",
            "time": "2026-09-29T05:57:00Z", "score": "822.0"}
    assert value(SCORE, body, "hardenedBaselineCompliance") == 82
    assert value(SCORE, dict(body, score=9), "hardenedBaselineCompliance") == 1
    assert value(SCORE, dict(body, score=0), "hardenedBaselineCompliance") == 0


def test_configuration_score_without_a_usable_score_is_not_evaluated():
    for body in NO_EVIDENCE + ({"score": "n/a"}, {"score": 1500}, {"score": -1}, {"score": True},
                               {"Results": [{"AvgWeightedScore": 90}]}):
        assert value(SCORE, body, "hardenedBaselineCompliance") is None
        assert collection_errors(SCORE, body)


def machine(os_platform, status="Onboarded", health="Active"):
    return {"osPlatform": os_platform, "onboardingStatus": status, "healthStatus": health, "isExcluded": False}


def test_server_coverage_counts_onboarded_servers():
    body = {"value": [machine("WindowsServer2022"), machine("WindowsServer2019", "CanBeOnboarded"), machine("Windows11")]}
    assert value(SERVER, body, "serverCoveragePercentage") == 50


def test_server_coverage_with_no_server_is_not_evaluated():
    body = {"value": [machine("Windows11"), machine("iOS")]}
    assert value(SERVER, body, "serverCoveragePercentage") is None
    assert collection_errors(SERVER, body)


def test_server_coverage_with_pages_left_is_not_evaluated():
    body = {"value": [machine("WindowsServer2022")], "@odata.nextLink": "https://api.securitycenter.microsoft.com/api/machines?$skip=10000"}
    assert value(SERVER, body, "serverCoveragePercentage") is None


def test_edr_deployed_needs_an_onboarded_machine():
    assert value(EDR, {"value": [machine("Windows11"), machine("Windows10", "CanBeOnboarded")]}, "isEDRDeployed") is True
    assert value(EDR, {"value": [machine("Windows11", "CanBeOnboarded")]}, "isEPPDeployed") is False
    assert value(EDR, {"value": []}, "isEDRDeployed") is None
    assert value(EDR, {"value": [dict(machine("Windows11"), isExcluded=True)]}, "isEDRDeployed") is None


def row(scid, compliant, applicable="1"):
    return {"DeviceId": "d", "DeviceName": "n", "ConfigurationId": scid, "IsCompliant": compliant, "IsApplicable": applicable}


def hunting(rows):
    return {"Stats": {}, "Schema": [{"Name": "IsCompliant", "Type": "SByte"}], "Results": rows}


def test_tamper_protection_needs_every_applicable_device():
    assert value(SCID, hunting([row("scid-2003", "1"), row("scid-2003", "1"), row("scid-2003", "None", "0")]),
                 "isTamperProtectionEnabled") is True
    out = SCID.transform(hunting([row("scid-2003", "1"), row("scid-2003", "0")]))["transformedResponse"]
    assert out["isTamperProtectionEnabled"] is False
    assert out["tamperProtectionCompliancePercentage"] == 50


def test_real_time_protection_reads_its_own_scid():
    out = SCID.transform(hunting([row("scid-2012", True), row("scid-2012", False)]))["transformedResponse"]
    assert out["isRealTimeProtectionEnabled"] is False
    assert out["realTimeProtectionCompliancePercentage"] == 50
    assert out["isTamperProtectionEnabled"] is None


def test_no_applicable_device_is_not_evaluated():
    for body in (hunting([]), hunting([row("scid-2003", "None", "0")])):
        assert value(SCID, body, "isTamperProtectionEnabled") is None
        assert collection_errors(SCID, body)


def test_unexpected_scid_and_no_evidence_are_not_evaluated():
    assert value(SCID, hunting([row("scid-90", "1")]), "isTamperProtectionEnabled") is None
    for module, key in ((SERVER, "serverCoveragePercentage"), (EDR, "isEDRDeployed"),
                        (SCID, "isTamperProtectionEnabled"), (SCID, "isRealTimeProtectionEnabled")):
        for body in NO_EVIDENCE:
            assert value(module, body, key) is None
