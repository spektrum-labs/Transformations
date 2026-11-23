"""Defender requiredcoveragepercentage and microsoft_endpoint_oneclick: the EDR server / workstation split.

The split is reported under new edr* keys only. The one-click transform's existing serverCoveragePercentage
and totalServerCount are live criteria elsewhere, so they keep exactly their old rule and values (0 for no
server, "server" in osPlatform only); the rulings below apply to the edr* keys alone.

Classification on osPlatform (rulings applied 2026-10-16): containing "server" is a server; any Linux
distribution is a server; Windows client versions (Windows10, Windows11, ...) and macOS are workstations;
anything else (iOS, Android, missing) is unclassified. Both transforms classify the machines they already
divide by (eligible: not excluded, not Unsupported / InsufficientInfo) and count a machine as protected
when it is Onboarded, exactly as the blended figure does. A class with no machine is None, never 0; a
partial or failed read gives None for the split. Synthetic machines only.
"""
import importlib.util
from pathlib import Path


def load(name):
    spec = importlib.util.spec_from_file_location("split_" + name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


LEGACY = load("requiredcoveragepercentage")
ONECLICK = load("microsoft_endpoint_oneclick")
BOTH = (LEGACY, ONECLICK)
SPLIT_KEYS = ("edrServerCoveragePercentage", "edrWorkstationCoveragePercentage", "edrTotalServerCount",
              "edrProtectedServerCount", "edrTotalWorkstationCount", "edrProtectedWorkstationCount",
              "edrUnclassifiedDeviceCount")


def machine(os_platform, status="Onboarded", excluded=False):
    record = {"onboardingStatus": status, "healthStatus": "Active", "lastSeen": "2026-10-15T00:00:00Z",
              "isExcluded": excluded}
    if os_platform is not None:
        record["osPlatform"] = os_platform
    return record


def run(module, payload):
    return module.transform(payload)


def out(module, payload):
    return run(module, payload)["transformedResponse"]


def test_mixed_fleet_one_unprotected_server_with_blended_coverage_at_least_95():
    machines = [machine("Windows11") for _ in range(60)] + [machine("Windows10") for _ in range(30)]
    machines += [machine("WindowsServer2022") for _ in range(9)] + [machine("WindowsServer2019", "CanBeOnboarded")]
    for module in BOTH:
        result = out(module, {"value": machines})
        assert result["requiredCoveragePercentage"] == 99
        assert (result["edrTotalServerCount"], result["edrProtectedServerCount"]) == (10, 9)
        assert result["edrServerCoveragePercentage"] == 90
        assert (result["edrTotalWorkstationCount"], result["edrProtectedWorkstationCount"]) == (90, 90)
        assert result["edrWorkstationCoveragePercentage"] == 100
        assert result["edrUnclassifiedDeviceCount"] == 0


def test_linux_is_a_server_and_macos_is_a_workstation():
    machines = [machine("Linux"), machine("Ubuntu", "CanBeOnboarded"), machine("RedHatEnterpriseLinux"),
                machine("macOS"), machine("MacOS", "CanBeOnboarded"), machine("Windows11"),
                machine("Windows8.1"), machine("WindowsServer2016")]
    for module in BOTH:
        result = out(module, {"value": machines})
        assert (result["edrTotalServerCount"], result["edrProtectedServerCount"]) == (4, 3)
        assert result["edrServerCoveragePercentage"] == 75
        assert (result["edrTotalWorkstationCount"], result["edrProtectedWorkstationCount"]) == (4, 3)
        assert result["edrWorkstationCoveragePercentage"] == 75
        assert result["edrUnclassifiedDeviceCount"] == 0


def test_no_servers_means_server_coverage_is_none_not_zero():
    machines = [machine("Windows11"), machine("Windows10", "CanBeOnboarded")]
    for module in BOTH:
        result = out(module, {"value": machines})
        assert result["edrServerCoveragePercentage"] is None
        assert result["edrTotalServerCount"] == 0
        assert result["edrWorkstationCoveragePercentage"] == 50
    for module in BOTH:
        result = out(module, {"value": [machine("WindowsServer2022")]})
        assert result["edrWorkstationCoveragePercentage"] is None
        assert result["edrServerCoveragePercentage"] == 100


def test_unclassifiable_machine_counts_in_neither_class():
    machines = [machine("Windows11"), machine("WindowsServer2022"), machine("iOS"), machine("Android"),
                machine(None), machine("WindowsIoTSomething")]
    for module in BOTH:
        result = out(module, {"value": machines})
        assert result["edrUnclassifiedDeviceCount"] == 4
        assert result["edrTotalServerCount"] == 1
        assert result["edrTotalWorkstationCount"] == 1


def test_split_counts_only_the_machines_the_blend_divides_by():
    machines = [machine("WindowsServer2022"), machine("WindowsServer2019", excluded=True),
                machine("Windows11", "Unsupported"), machine("Linux", "InsufficientInfo"), machine("Windows11")]
    for module in BOTH:
        result = out(module, {"value": machines})
        assert result["edrTotalServerCount"] == 1
        assert result["edrTotalWorkstationCount"] == 1
        assert result["edrUnclassifiedDeviceCount"] == 0


def test_legacy_existing_fields_are_unchanged():
    machines = [machine("Windows11") for _ in range(19)] + [machine("WindowsServer2022", "CanBeOnboarded"),
                                                            machine("Windows10", "Unsupported")]
    response = run(LEGACY, {"value": machines})
    result = response["transformedResponse"]
    existing = {"requiredCoveragePercentage": 95, "allDevicesPercentageofCoverage": 90,
                "eligibleDevicesPercentageofCoverage": 95, "allDevices": 21, "eligibleDevices": 20,
                "protectedDevices": 19}
    assert {k: result[k] for k in existing} == existing
    assert set(result) == set(existing) | set(SPLIT_KEYS)
    assert response["additionalInfo"]["evaluation"]["passReasons"] == [
        "Overall coverage: 19/21 total devices (90%)",
        "1 device(s) excluded from eligibility (Unsupported/InsufficientInfo)"]
    assert response["additionalInfo"]["transformation"]["inputSummary"] == {
        "allDevices": 21, "eligibleDevices": 20, "protectedDevices": 19}


def test_oneclick_existing_fields_are_unchanged():
    machines = [machine("Windows11") for _ in range(19)] + [machine("WindowsServer2022", "CanBeOnboarded")]
    response = run(ONECLICK, {"value": machines})
    result = response["transformedResponse"]
    existing = {"isEPPEnabled": True, "isEPPConfigured": False, "isEPPLoggingEnabled": True,
                "requiredCoveragePercentage": 95, "serverCoveragePercentage": 0, "totalEndpointCount": 20,
                "totalServerCount": 1, "eligibleDevices": 20, "protectedDevices": 19, "reportingDevices": 19}
    assert {k: result[k] for k in existing} == existing
    assert set(result) == set(existing) | set(SPLIT_KEYS)
    assert response["additionalInfo"]["evaluation"]["failReasons"] == [
        "19 of 20 eligible machines are onboarded to Defender for Endpoint (95%)",
        "19 of 19 onboarded machines report an active sensor",
        "1 eligible servers in the inventory (0% onboarded)",
        "isEPPConfigured failed"]


def test_oneclick_live_server_keys_keep_the_old_rule():
    # No server: the live serverCoveragePercentage stays 0, while the new edr key is None.
    response = run(ONECLICK, {"value": [machine("Windows11")]})
    assert "0 eligible servers in the inventory (0% onboarded)" in response["additionalInfo"]["evaluation"]["passReasons"]
    result = response["transformedResponse"]
    assert result["serverCoveragePercentage"] == 0
    assert result["totalServerCount"] == 0
    assert result["edrServerCoveragePercentage"] is None
    # Linux: not a server under the live keys' old rule, a server under the edr keys.
    result = out(ONECLICK, {"value": [machine("Linux", "CanBeOnboarded"), machine("WindowsServer2022"),
                                      machine("Windows11")]})
    assert (result["totalServerCount"], result["serverCoveragePercentage"]) == (1, 100)
    assert (result["edrTotalServerCount"], result["edrServerCoveragePercentage"]) == (2, 50)


def test_legacy_partial_or_failed_read_gives_none_for_every_split_field():
    pages_left = {"value": [machine("WindowsServer2022"), machine("Windows11")],
                  "@odata.nextLink": "https://api.example.invalid/api/machines?$skip=10000"}
    for payload in (pages_left, {}, {"error": {"code": "Forbidden"}}, {"value": []},
                    {"value": [machine("Windows11", "Unsupported")]}, "not json"):
        response = run(LEGACY, payload)
        assert response["additionalInfo"]["dataCollection"]["status"] == "error"
        for key in SPLIT_KEYS:
            assert response["transformedResponse"].get(key) is None, key


def test_oneclick_partial_or_failed_read_gives_none_for_the_edr_fields():
    pages_left = {"value": [machine("WindowsServer2022"), machine("Windows11")],
                  "@odata.nextLink": "https://api.example.invalid/api/machines?$skip=10000"}
    result = out(ONECLICK, pages_left)
    for key in SPLIT_KEYS:
        assert result[key] is None, key
    # Existing fields keep today's values on that path.
    assert result["requiredCoveragePercentage"] == 100
    assert (result["totalServerCount"], result["serverCoveragePercentage"]) == (1, 100)
    for payload in ({}, {"error": {"code": "Forbidden"}}, {"value": []}, {"value": [machine("iOS", "Unsupported")]}):
        response = run(ONECLICK, payload)
        assert response["additionalInfo"]["dataCollection"]["status"] == "error"
        for key in SPLIT_KEYS:
            assert response["transformedResponse"].get(key) is None, key


def fleet(n_servers, bad_servers, n_workstations, bad_workstations):
    machines = [machine("WindowsServer2022", "CanBeOnboarded" if i < bad_servers else "Onboarded")
                for i in range(n_servers)]
    machines += [machine("Windows11", "CanBeOnboarded" if i < bad_workstations else "Onboarded")
                 for i in range(n_workstations)]
    return {"value": machines}


def test_edr_percentages_never_round_up_to_a_boundary():
    # 100 only when every machine in the class is onboarded; 94.9 stays below a 95 bar.
    for module in BOTH:
        for servers, bad, want in ((200, 1, 99.5), (2000, 1, 99.95), (20000, 1, 99.99), (200, 0, 100)):
            assert out(module, fleet(servers, bad, 0, 0))["edrServerCoveragePercentage"] == want
        assert out(module, fleet(0, 0, 1000, 51))["edrWorkstationCoveragePercentage"] == 94.9
        assert out(module, fleet(0, 0, 3, 1))["edrWorkstationCoveragePercentage"] == 66.66
        assert out(module, fleet(0, 0, 1000, 50))["edrWorkstationCoveragePercentage"] == 95


def test_existing_fields_keep_their_rounding():
    # Only the edr* fields floor; the existing figures keep their rounding (199/200 -> 100).
    assert out(LEGACY, fleet(200, 1, 0, 0))["requiredCoveragePercentage"] == 100
    result = out(ONECLICK, fleet(200, 1, 0, 0))
    assert (result["requiredCoveragePercentage"], result["serverCoveragePercentage"]) == (100, 100)


def test_windows_client_platform_variants_are_workstations():
    variants = ["Windows7", "Windows8", "Windows8.1", "Windows8Blue", "Windows10", "Windows10WVD",
                "Windows11", "Windows11WVD", "WindowsXP", "WindowsVista"]
    for module in BOTH:
        result = out(module, {"value": [machine(v) for v in variants]})
        assert result["edrTotalWorkstationCount"] == len(variants)
        assert result["edrUnclassifiedDeviceCount"] == 0
        # A server build still reads as a server, and an unknown Windows value stays unclassified.
        result = out(module, {"value": [machine("WindowsServer2022"), machine("Windows"), machine("WindowsIoT")]})
        assert (result["edrTotalServerCount"], result["edrTotalWorkstationCount"]) == (1, 0)
        assert result["edrUnclassifiedDeviceCount"] == 2
