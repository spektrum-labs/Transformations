import importlib.util
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("microsoft_endpoint_oneclick.py")
SPEC = importlib.util.spec_from_file_location("microsoft_endpoint_oneclick", MODULE_PATH)
TRANSFORM = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TRANSFORM)


def _result(payload):
    return TRANSFORM.transform(payload)["transformedResponse"]


def test_empty_machine_inventory_never_reports_coverage_or_epp_pass():
    result = _result({"value": []})
    assert result["requiredCoveragePercentage"] == 0
    assert result["serverCoveragePercentage"] == 0
    assert result["totalEndpointCount"] == 0
    assert result["isEPPEnabled"] is False
    assert result["isEPPConfigured"] is False
    assert result["isEPPLoggingEnabled"] is False


def test_machine_inventory_uses_onboarding_and_reporting_evidence():
    result = _result({"value": [
        {"onboardingStatus": "Onboarded", "healthStatus": "Active", "lastSeen": "2026-07-27", "osPlatform": "Windows11"},
        {"onboardingStatus": "CanBeOnboarded", "healthStatus": "NoSensorData", "osPlatform": "WindowsServer2022"},
    ]})
    assert result["isEPPEnabled"] is True
    assert result["isEPPConfigured"] is False
    assert result["isEPPLoggingEnabled"] is True
    assert result["requiredCoveragePercentage"] == 50
    assert result["serverCoveragePercentage"] == 0


def test_inactive_sensor_does_not_pass_logging_check():
    result = _result({"value": [{
        "onboardingStatus": "Onboarded",
        "healthStatus": "Inactive",
        "lastSeen": "2026-07-27",
        "osPlatform": "Windows11",
    }]})
    assert result["isEPPEnabled"] is True
    assert result["isEPPLoggingEnabled"] is False


def test_string_false_does_not_exclude_machine():
    result = _result({"value": [{
        "isExcluded": "false",
        "onboardingStatus": "Onboarded",
        "healthStatus": "Active",
        "lastSeen": "2026-07-27",
        "osPlatform": "Windows11",
    }]})
    assert result["totalEndpointCount"] == 1
    assert result["requiredCoveragePercentage"] == 100


def test_empty_collection_fails_closed_for_machine_checks():
    result = _result({"value": []})
    assert result["totalEndpointCount"] == 0


def test_unrecognized_payload_is_a_collection_error():
    response = TRANSFORM.transform({"unexpected": []})
    assert response["transformedResponse"] == {}
    assert response["additionalInfo"]["dataCollection"]["status"] == "error"


def test_invalid_machine_record_is_a_collection_error():
    response = TRANSFORM.transform({"value": ["not-a-machine"]})
    assert response["transformedResponse"] == {}
    assert response["additionalInfo"]["dataCollection"]["status"] == "error"
