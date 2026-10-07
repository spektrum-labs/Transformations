"""Endpoint rules (2026-09-29) for Sophos and NinjaOne endpoint checks (synthetic data):
a device is judged only when seen within 15 days of the newest check-in, and when the newest check-in is
itself older than that the whole fleet is dark and every device is stale; phones and tablets are out of
NinjaOne EPP percentages; a NinjaOne Mac whose third-party AV is not ON is unreadable, not unprotected."""
import importlib.util
import pathlib
from datetime import datetime, timedelta, timezone

HERE = pathlib.Path(__file__).resolve().parent
SOPHOS_EPP = HERE.parent / "1BC425FA-0638-4BF1-8194-19E7E4F2F43C" / "epp_transform.py"
NINJA = HERE / "ninjaone-endpoint-management"


def load(path):
    spec = importlib.util.spec_from_file_location("rules_" + path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def out(path, body):
    return load(path)(body)["transformedResponse"]


NOW = datetime.now(timezone.utc)


def iso(days_ago):
    return (NOW - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def epoch(days_ago):
    return str((NOW - timedelta(days=days_ago)).timestamp())


def sophos_computer(days_ago):
    return {"type": "computer", "lastSeenAt": iso(days_ago),
            "assignedProducts": [{"code": "endpointProtection", "status": "installed"}],
            "health": {"overall": "good", "services": {"status": "good", "serviceDetails": []}}}


class TestSophosActiveWindow:
    def test_endpoint_older_than_window_is_left_out_and_counted(self):
        body = {"items": [sophos_computer(1), sophos_computer(20)]}
        result = out(SOPHOS_EPP, body)
        assert result["staleEndpointCount"] == 1
        assert result["requiredCoveragePercentage"] == 100

    def test_dark_fleet_makes_every_endpoint_stale(self):
        body = {"items": [sophos_computer(30), sophos_computer(31)]}
        result = out(SOPHOS_EPP, body)
        assert result["staleEndpointCount"] == 2
        # Not 0%. A fleet whose newest check-in predates the active window leaves every coverage
        # denominator empty, and percentage(0, 0) is 0, which graded as a measured failure of an
        # estate nobody saw. The whole read is now Unevaluated and only the stale count survives
        # (PR #1067 review, 2026-10-07).
        assert result["requiredCoveragePercentage"] is None

    def test_stale_sensor_count_sees_a_dark_fleet(self):
        body = {"items": [sophos_computer(30), sophos_computer(31)]}
        assert out(HERE / "sophos" / "staleSensorCount.py", body)["staleSensorCount"] == 2

    def test_stale_sensor_count_fresh_fleet_is_zero(self):
        body = {"items": [sophos_computer(1), sophos_computer(3)]}
        assert out(HERE / "sophos" / "staleSensorCount.py", body)["staleSensorCount"] == 0

    def test_stale_sensor_count_without_a_list_is_not_evaluated(self):
        assert out(HERE / "sophos" / "staleSensorCount.py", {})["staleSensorCount"] is None


def av_row(device_id, product, state, days_ago):
    return {"deviceId": device_id, "productName": product, "productState": state, "timestamp": epoch(days_ago)}


class TestNinjaOneAntivirusRules:
    path = NINJA / "requiredCoveragePercentage.py"

    def test_stale_row_is_left_out(self):
        body = {"results": [av_row(1, "Defender", "ON", 1), av_row(2, "Defender", "OFF", 20)]}
        result = out(self.path, body)
        assert result["requiredCoveragePercentage"] == 100
        assert result["devicesLeftOutStale"] == 1

    def test_dark_fleet_is_not_evaluated(self):
        body = {"results": [av_row(1, "Defender", "ON", 30), av_row(2, "Defender", "ON", 31)]}
        result = out(self.path, body)
        assert result["requiredCoveragePercentage"] is None
        assert result["fleetDark"] is True
        assert result["devicesLeftOutStale"] == 2

    def test_mac_third_party_off_is_unreadable(self):
        body = {"results": [av_row(1, "SOPHOS Central", "OFF", 1), av_row(2, "Defender", "ON", 1)],
                "devices": [{"id": 1, "nodeClass": "MAC"}, {"id": 2, "nodeClass": "WINDOWS_WORKSTATION"}]}
        result = out(self.path, body)
        assert result["requiredCoveragePercentage"] == 100
        assert result["macDevicesUnreadable"] == 1

    def test_mac_reporting_none_is_still_unprotected(self):
        body = {"results": [{"deviceId": 1, "productName": "NONE"}, av_row(2, "Defender", "ON", 1)],
                "devices": [{"id": 1, "nodeClass": "MAC"}, {"id": 2, "nodeClass": "WINDOWS_WORKSTATION"}]}
        assert out(self.path, body)["requiredCoveragePercentage"] == 50

    def test_windows_off_is_still_unprotected(self):
        body = {"results": [av_row(1, "Sophos", "OFF", 1)], "devices": [{"id": 1, "nodeClass": "WINDOWS_WORKSTATION"}]}
        assert out(self.path, body)["requiredCoveragePercentage"] == 0


def device(device_id, node_class, policy, days_ago):
    return {"id": device_id, "nodeClass": node_class, "policyId": policy, "lastContact": epoch(days_ago)}


class TestNinjaOneDeviceRules:
    def test_phones_and_stale_devices_leave_the_policy_percentage(self):
        body = {"data": [device(1, "MAC", "37", 1), device(2, "MAC", [], 20), device(3, "APPLE_IOS", [], 1)]}
        result = out(NINJA / "isEPPConfigured.py", body)
        assert result["isEPPConfigured"] == 100
        assert result["devicesLeftOutMobile"] == 1
        assert result["devicesLeftOutStale"] == 1

    def test_dark_fleet_policy_percentage_is_not_evaluated(self):
        body = {"data": [device(1, "MAC", "37", 30), device(2, "MAC", "37", 31)]}
        result = out(NINJA / "isEPPConfigured.py", body)
        assert result["isEPPConfigured"] is None
        assert result["fleetDark"] is True

    def test_stale_sensor_count_sees_a_dark_fleet(self):
        body = {"data": [{"id": 1, "systemName": "a", "lastContact": epoch(30)},
                         {"id": 2, "systemName": "b", "lastContact": epoch(31)}]}
        assert out(NINJA / "staleSensorCount.py", body)["staleSensorCount"] == 2

    def test_stale_sensor_count_uses_the_newest_contact_in_a_live_fleet(self):
        body = {"data": [{"id": 1, "systemName": "a", "lastContact": epoch(1)},
                         {"id": 2, "systemName": "b", "lastContact": epoch(20)}]}
        assert out(NINJA / "staleSensorCount.py", body)["staleSensorCount"] == 1
