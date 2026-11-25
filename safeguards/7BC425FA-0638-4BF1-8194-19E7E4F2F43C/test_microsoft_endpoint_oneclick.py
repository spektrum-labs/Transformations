import importlib.util
from datetime import datetime, timedelta, timezone
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("microsoft_endpoint_oneclick.py")
SPEC = importlib.util.spec_from_file_location("microsoft_endpoint_oneclick", MODULE_PATH)
TRANSFORM = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TRANSFORM)


def ago(days):
    return (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.0000000Z")


def _result(payload):
    return TRANSFORM.transform(payload)["transformedResponse"]


def test_empty_machine_inventory_never_reports_coverage_or_epp_pass():
    result = _result({"value": []})
    assert result["requiredCoveragePercentage"] is None
    assert result["serverCoveragePercentage"] is None
    assert result["totalEndpointCount"] == 0
    assert result["isEPPEnabled"] is None
    assert result["isEPPConfigured"] is None
    assert result["isEPPLoggingEnabled"] is None


def test_machine_inventory_uses_onboarding_and_reporting_evidence():
    result = _result({"value": [
        {"onboardingStatus": "Onboarded", "healthStatus": "Active", "lastSeen": ago(1), "osPlatform": "Windows11"},
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


def test_nested_response_wrapper_is_unwrapped():
    result = _result({"response": {"value": [{
        "onboardingStatus": "Onboarded",
        "healthStatus": "Active",
        "lastSeen": "2026-07-27",
        "osPlatform": "Windows11",
    }]}})
    assert result["totalEndpointCount"] == 1
    assert result["isEPPEnabled"] is True


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


def machine(health="Active", days_ago=1, platform="Windows11", status="Onboarded"):
    return {"onboardingStatus": status, "healthStatus": health, "lastSeen": ago(days_ago), "osPlatform": platform}


def test_dormant_inactive_device_is_left_out_of_logging():
    """An idle phone or shelved laptop reads healthStatus Inactive. It is dormant, not a broken sensor."""
    result = _result({"value": [machine(), machine(), machine(health="Inactive", days_ago=9, platform="iOS"),
                                machine(health="Inactive", days_ago=12)]})
    assert result["isEPPLoggingEnabled"] is True
    assert result["loggingJudgedDevices"] == 2
    assert result["loggingExcludedInactiveDevices"] == 2


def test_device_not_seen_within_window_of_newest_is_left_out_of_logging():
    result = _result({"value": [machine(), machine(health="NoSensorData", days_ago=40)]})
    assert result["isEPPLoggingEnabled"] is True
    assert result["loggingExcludedStaleDevices"] == 1


def test_recent_impaired_sensor_still_fails_logging():
    result = _result({"value": [machine(), machine(health="ImpairedCommunication", days_ago=2),
                                machine(health="Inactive", days_ago=10)]})
    assert result["isEPPLoggingEnabled"] is False
    assert result["loggingJudgedDevices"] == 2


def test_every_onboarded_device_dormant_fails_logging():
    result = _result({"value": [machine(health="Inactive", days_ago=9), machine(health="Inactive", days_ago=10)]})
    assert result["isEPPLoggingEnabled"] is False
    assert result["loggingJudgedDevices"] == 0


def test_dark_fleet_fails_logging():
    result = _result({"value": [machine(days_ago=30), machine(days_ago=31)]})
    assert result["isEPPEnabled"] is True
    assert result["isEPPLoggingEnabled"] is False
    assert result["loggingExcludedStaleDevices"] == 2


def test_active_machine_without_last_seen_never_passes_logging():
    # Follow-up review of #1442: an Active machine with no lastSeen was judged and passed logging.
    result = _result({"value": [
        {"onboardingStatus": "Onboarded", "healthStatus": "Active", "osPlatform": "Windows11"},
    ]})
    assert result["isEPPLoggingEnabled"] is False
    assert result["loggingJudgedDevices"] == 0 and result["loggingExcludedUndatedDevices"] == 1


def test_machine_without_last_seen_is_left_out_and_reported():
    result = _result({"value": [
        {"onboardingStatus": "Onboarded", "healthStatus": "Active", "lastSeen": ago(1), "osPlatform": "Windows11"},
        {"onboardingStatus": "Onboarded", "healthStatus": "Active", "lastSeen": "not a date", "osPlatform": "Windows11"},
        {"onboardingStatus": "Onboarded", "healthStatus": "Active", "osPlatform": "Windows11"},
    ]})
    assert result["isEPPLoggingEnabled"] is True
    assert result["loggingJudgedDevices"] == 1 and result["loggingExcludedUndatedDevices"] == 2
    response = TRANSFORM.transform({"value": [
        {"onboardingStatus": "Onboarded", "healthStatus": "Active", "lastSeen": ago(1), "osPlatform": "Windows11"},
        {"onboardingStatus": "Onboarded", "healthStatus": "Active", "osPlatform": "Windows11"},
    ]})
    reasons = " ".join(response["additionalInfo"]["evaluation"]["passReasons"]
                       + response["additionalInfo"]["evaluation"]["failReasons"])
    assert "1 with no readable lastSeen" in reasons


def test_undated_unhealthy_machines_count_against_logging():
    # Second review: one dated Active machine beside 999 undated ImpairedCommunication machines read True.
    machines = [{"onboardingStatus": "Onboarded", "healthStatus": "Active", "lastSeen": ago(1), "osPlatform": "Windows11"}]
    machines += [{"onboardingStatus": "Onboarded", "healthStatus": "ImpairedCommunication", "osPlatform": "Windows11"}
                 for _ in range(999)]
    result = _result({"value": machines})
    assert result["isEPPLoggingEnabled"] is False
    assert result["loggingJudgedDevices"] == 1000 and result["loggingExcludedUndatedDevices"] == 0


def test_undated_machine_states_each_go_their_own_way():
    base = {"onboardingStatus": "Onboarded", "osPlatform": "Windows11"}
    dated = dict(base, healthStatus="Active", lastSeen=ago(1))
    result = _result({"value": [dated, dict(base, healthStatus="Inactive"), dict(base, healthStatus="Active")]})
    assert result["isEPPLoggingEnabled"] is True
    assert result["loggingExcludedInactiveDevices"] == 1 and result["loggingExcludedUndatedDevices"] == 1
    for health in ("NoSensorData", None):
        result = _result({"value": [dated, dict(base, healthStatus=health)]})
        assert result["isEPPLoggingEnabled"] is False, health
