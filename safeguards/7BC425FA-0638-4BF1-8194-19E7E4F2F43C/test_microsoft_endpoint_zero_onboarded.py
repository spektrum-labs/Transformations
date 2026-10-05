"""Defender for Endpoint (One-Click) connected with 0 onboarded devices is a finding for that tool.

A readable machine inventory (HTTP 200, a value array, no pages left) with no onboarded machine means the
tool is connected and protects nothing. Device-coverage checks give a definite result that says so; they
are not "not evaluated". Error bodies, unread pages and the advanced-hunting checks (which never see the
machine list) stay not evaluated. Tenants with onboarded machines keep their values.
Synthetic bodies only; no customer data.
"""
import importlib.util
from pathlib import Path


def load(name):
    spec = importlib.util.spec_from_file_location("zero_" + name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ONECLICK = load("microsoft_endpoint_oneclick")
CONFIGURED = load("microsoft_endpoint_iseppconfigured")
EDR = load("microsoft_endpoint_edrdeployed")
SERVER = load("microsoft_endpoint_servercoverage")
SCID = load("microsoft_endpoint_scid_compliance")
ZERO = "Defender for Endpoint is connected and has 0 onboarded devices"
EMPTY = {"@odata.context": "https://api.securitycenter.microsoft.com/api/$metadata#Machines", "value": []}
ERRORS = (None, {}, "", {"error": {"code": "Forbidden", "message": "Missing application roles"}},
          {"error": True, "message": "HTTP 403"}, {"statusCode": 401, "error": "Unauthorized"})


def machine(os_platform="Windows11", status="Onboarded", health="Active", excluded=False):
    return {"osPlatform": os_platform, "onboardingStatus": status, "healthStatus": health,
            "isExcluded": excluded, "lastSeen": "2026-01-01T00:00:00Z"}


DISCOVERED_ONLY = {"value": [machine(status="CanBeOnboarded"), machine("WindowsServer2022", "CanBeOnboarded")]}
FLEET = {"value": [machine(), machine(health="Inactive"), machine("WindowsServer2022"),
                   machine("WindowsServer2019", "CanBeOnboarded"), machine("iOS", "Unsupported")]}


def out(module, body):
    return module.transform(body)


def value(module, body, key):
    return out(module, body)["transformedResponse"].get(key)


def collected(module, body):
    return out(module, body)["additionalInfo"]["dataCollection"]["status"]


def fail_reasons(module, body):
    return out(module, body)["additionalInfo"]["evaluation"]["failReasons"]


# ---- coverage checks give a definite, tool-scoped finding on 0 onboarded devices

def test_oneclick_empty_inventory_says_zero_onboarded_first():
    for body in (EMPTY, DISCOVERED_ONLY, dict(EMPTY, **{"@odata.nextLink": None})):
        result = out(ONECLICK, body)
        tr = result["transformedResponse"]
        assert tr["isEPPEnabled"] is False and tr["isEPPLoggingEnabled"] is False
        assert tr["requiredCoveragePercentage"] == 0 and tr["protectedDevices"] == 0
        assert result["additionalInfo"]["dataCollection"]["status"] == "success"
        reasons = result["additionalInfo"]["evaluation"]["failReasons"]
        assert reasons[0].startswith(ZERO)
        assert result["additionalInfo"]["evaluation"]["recommendations"]
    assert "inventory is empty" in fail_reasons(ONECLICK, EMPTY)[0]
    assert "2 eligible machines" in fail_reasons(ONECLICK, DISCOVERED_ONLY)[0]


def test_iseppconfigured_zero_onboarded_is_zero_not_unevaluated():
    for body in (EMPTY, DISCOVERED_ONLY, {"value": [machine(excluded=True)]}):
        assert value(CONFIGURED, body, "isEPPConfigured") == 0
        assert type(value(CONFIGURED, body, "isEPPConfigured")) is int
        assert collected(CONFIGURED, body) == "success"
        assert fail_reasons(CONFIGURED, body)[0].startswith(ZERO)


def test_edr_and_epp_deployed_zero_onboarded_fail_with_the_reason():
    for body in (EMPTY, DISCOVERED_ONLY):
        assert value(EDR, body, "isEDRDeployed") is False
        assert value(EDR, body, "isEPPDeployed") is False
        assert collected(EDR, body) == "success"
        assert fail_reasons(EDR, body)[0].startswith(ZERO)


def test_server_coverage_zero_onboarded_is_a_finding():
    for body in (EMPTY, DISCOVERED_ONLY):
        assert value(SERVER, body, "serverCoveragePercentage") == 0
        assert collected(SERVER, body) == "success"
        assert fail_reasons(SERVER, body)[0].startswith(ZERO)


def test_server_coverage_with_devices_but_no_server_stays_not_evaluated():
    body = {"value": [machine(), machine("macOS")]}
    assert value(SERVER, body, "serverCoveragePercentage") is None
    assert collected(SERVER, body) == "error"
    assert "holds no server" in fail_reasons(SERVER, body)[0]


# ---- real errors and unread pages stay not evaluated

def test_error_bodies_and_unread_pages_stay_not_evaluated():
    paged = dict(EMPTY, **{"@odata.nextLink": "https://api.securitycenter.microsoft.com/api/machines?$skiptoken=x"})
    for body in ERRORS + (paged, {"value": "not-a-list"}, {"value": ["not-a-machine"]}):
        assert value(CONFIGURED, body, "isEPPConfigured") is None
        assert value(EDR, body, "isEDRDeployed") is None
        assert value(SERVER, body, "serverCoveragePercentage") is None
        for module in (CONFIGURED, EDR, SERVER):
            assert collected(module, body) == "error"
            assert not any(r.startswith(ZERO) for r in fail_reasons(module, body))
    for body in ERRORS + ({"value": "not-a-list"}, {"value": ["not-a-machine"]}):
        assert out(ONECLICK, body)["transformedResponse"] == {}
        assert collected(ONECLICK, body) == "error"


def test_stringified_empty_inventory_is_read_the_same():
    import json
    assert value(CONFIGURED, json.dumps(EMPTY), "isEPPConfigured") == 0
    assert value(EDR, json.dumps(EMPTY), "isEDRDeployed") is False


# ---- advanced hunting never sees the machine list: no invented verdict, exact reason

def hunting(rows):
    return {"Stats": {}, "Schema": [{"Name": "IsCompliant", "Type": "SByte"}], "Results": rows}


def test_empty_assessment_stays_not_evaluated_and_claims_nothing_about_devices():
    result = out(SCID, hunting([]))
    assert result["transformedResponse"]["isTamperProtectionEnabled"] is None
    assert result["transformedResponse"]["isRealTimeProtectionEnabled"] is None
    assert result["additionalInfo"]["dataCollection"]["status"] == "error"
    reason = result["additionalInfo"]["dataCollection"]["errors"][0]
    assert "returned no device" in reason and "cannot show whether any device is onboarded" in reason
    assert ZERO not in reason


def test_assessment_with_no_applicable_device_names_the_count():
    rows = [{"DeviceId": "d" + str(i), "DeviceName": "n", "ConfigurationId": "scid-2010",
             "IsCompliant": None, "IsApplicable": 0} for i in range(3)]
    result = out(SCID, hunting(rows))
    assert result["transformedResponse"]["isTamperProtectionEnabled"] is None
    assert result["additionalInfo"]["dataCollection"]["errors"] == [
        "Defender for Endpoint's secure-configuration assessment lists 3 devices for tamper protection "
        "(scid-2010) and none is applicable, so Defender for Endpoint does not measure tamper protection here"]


# ---- tenants with onboarded machines keep their values

def test_onboarded_fleet_values_are_unchanged():
    tr = out(ONECLICK, FLEET)["transformedResponse"]
    assert tr == {"isEPPEnabled": True, "isEPPConfigured": False, "isEPPLoggingEnabled": False,
                  "requiredCoveragePercentage": 75, "serverCoveragePercentage": 50, "totalEndpointCount": 4,
                  "totalServerCount": 2, "eligibleDevices": 4, "protectedDevices": 3, "reportingDevices": 2}
    assert value(CONFIGURED, FLEET, "isEPPConfigured") == 100
    assert value(EDR, FLEET, "isEDRDeployed") is True
    assert value(SERVER, FLEET, "serverCoveragePercentage") == 50
    assert collected(SERVER, FLEET) == "success"
    assert not any(r.startswith(ZERO) for m in (ONECLICK, CONFIGURED, EDR, SERVER)
                   for r in out(m, FLEET)["additionalInfo"]["evaluation"]["failReasons"])
    reasons = out(ONECLICK, FLEET)["additionalInfo"]["evaluation"]["failReasons"]
    assert reasons[0] == "3 of 4 eligible machines are onboarded to Defender for Endpoint (75%)"
