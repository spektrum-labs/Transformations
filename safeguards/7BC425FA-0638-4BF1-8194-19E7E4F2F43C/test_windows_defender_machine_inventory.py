"""Windows Defender (classic definition): EPP and coverage are measured from the machine inventory.

epp_transform.py was a copy of the Sophos transform run over GET /api/alerts, so one alert passed six
controls and a clean tenant failed them all; requiredcoveragepercentage.py scored 100 from an empty or
403 body, compared onboardingStatus against "Onboarded" while Microsoft documents "onboarded", and
never read lastSeen. The patch, removable-media and behavioral-monitoring files answered from the alert
list too; no Defender method wired to this definition evidences them, so they are not measured.

Bodies follow Microsoft Learn's published examples for GET /api/machines and GET /api/alerts
(envelope and field names verbatim; onboardingStatus values from the Machine resource property table;
identifiers synthetic). lastSeen is set relative to now so the cases do not age. Every case runs as
plain Python and compiled the way Token-Service runs it (tools/restricted_sandbox.py).
"""
import importlib.util
from datetime import datetime, timedelta
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
EPP_KEYS = ("isEPPEnabled", "isEPPDeployed", "isEDRDeployed", "isEPPLoggingEnabled")
COVERAGE = "requiredCoveragePercentage"


def native(name):
    spec = importlib.util.spec_from_file_location("wd_inventory_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def sandboxed(name):
    spec = importlib.util.spec_from_file_location("restricted_sandbox_wd_inventory", ROOT / "tools" / "restricted_sandbox.py")
    sandbox = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sandbox)
    return sandbox.load((HERE / (name + ".py")).read_text(), "<transformation>")["transform"]


RUNNERS = [pytest.param(native, id="native"), pytest.param(sandboxed, id="sandbox")]


def seen(days_ago):
    return (datetime.utcnow() - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%S.%f0Z")


def machine(status="onboarded", health="Active", days_ago=1, os_platform="Windows11", excluded=False):
    return {"id": "machine-" + status + "-" + str(days_ago), "computerDnsName": "host.example.invalid",
            "firstSeen": "2026-01-02T14:55:03.7791856Z", "lastSeen": seen(days_ago), "osPlatform": os_platform,
            "healthStatus": health, "onboardingStatus": status, "isExcluded": excluded, "riskScore": "Low"}


def machines(*records, **extra):
    body = {"@odata.context": "https://api.security.microsoft.com/api/$metadata#Machines", "value": list(records)}
    body.update(extra)
    return body


ALERT = {"id": "da000000000000000000_-000000000", "incidentId": 1001, "severity": "Low", "status": "New",
         "detectionSource": "WindowsDefenderAv", "category": "SuspiciousActivity", "title": "Suspicious behavior",
         "alertCreationTime": "2026-09-20T10:53:48.7657932Z", "machineId": "machine-1"}
ALERTS = {"@odata.context": "https://api.security.microsoft.com/api/$metadata#Alerts", "value": [ALERT]}
ALERTS_RETURNSPEC = {"alerts": [ALERT], "apiResponse": ALERTS}
NO_ALERTS = {"@odata.context": "https://api.security.microsoft.com/api/$metadata#Alerts", "value": []}
FORBIDDEN = {"error": {"code": "Forbidden", "message": "Insufficient privileges to complete the operation."}}


class Poisoned(dict):
    """A non-empty object whose every read raises, to drive the transform's except path."""

    def __init__(self):
        super().__init__(poisoned=True)

    def boom(self, *args, **kwargs):
        raise RuntimeError("poisoned read")

    get = __getitem__ = __contains__ = keys = items = values = __iter__ = boom

    def __len__(self):
        return 1


NO_EVIDENCE = [
    pytest.param(lambda: ALERTS, id="alert-list"),
    pytest.param(lambda: ALERTS_RETURNSPEC, id="alert-list-returnSpec"),
    pytest.param(lambda: NO_ALERTS, id="no-alerts"),
    pytest.param(lambda: FORBIDDEN, id="403"),
    pytest.param(lambda: machines(), id="empty-inventory"),
    pytest.param(lambda: machines(machine("Unsupported"), machine("InsufficientInfo")), id="zero-eligible"),
    pytest.param(lambda: machines(machine(excluded=True)), id="all-excluded"),
    pytest.param(lambda: machines(machine(), **{"@odata.nextLink": "https://api.security.microsoft.com/api/machines?$skip=1"}),
                 id="partial-page"),
    pytest.param(lambda: machines({"id": "m1", "lastSeen": seen(1), "healthStatus": "Active"}), id="no-onboardingStatus"),
    pytest.param(lambda: None, id="null"),
    pytest.param(Poisoned, id="poisoned"),
]


def collected(out):
    return out["additionalInfo"]["dataCollection"]["status"]


# ---- requiredCoveragePercentage

@pytest.mark.parametrize("loader", RUNNERS)
def test_coverage_counts_documented_lowercase_and_capitalised_onboarded_alike(loader):
    transform = loader("requiredcoveragepercentage")
    for status in ("onboarded", "Onboarded"):
        out = transform(machines(machine(status), machine(status, os_platform="WindowsServer2022"), machine("CanBeOnboarded")))
        # 2 of 3 is 66.67%, floored. The share is floored rather than rounded so it can never read
        # higher than it is; see test_coverage_does_not_round_up_to_a_pass.
        assert out["transformedResponse"][COVERAGE] == 66
        assert collected(out) == "success"


@pytest.mark.parametrize("loader", RUNNERS)
def test_coverage_is_100_only_when_every_eligible_machine_is_onboarded_and_reporting(loader):
    out = loader("requiredcoveragepercentage")(machines(machine(), machine(health="Inactive", days_ago=10), machine("Unsupported")))
    assert out["transformedResponse"][COVERAGE] == 100
    assert out["transformedResponse"]["eligibleDevices"] == 2
    assert collected(out) == "success"


@pytest.mark.parametrize("loader", RUNNERS)
def test_a_fleet_dark_for_180_days_is_not_covered(loader):
    out = loader("requiredcoveragepercentage")(machines(machine(health="Inactive", days_ago=180), machine(health="Inactive", days_ago=180)))
    assert out["transformedResponse"][COVERAGE] == 0
    assert out["transformedResponse"]["staleOnboardedDevices"] == 2
    assert collected(out) == "success"


@pytest.mark.parametrize("loader", RUNNERS)
def test_a_machine_past_the_window_stays_in_the_denominator(loader):
    out = loader("requiredcoveragepercentage")(machines(machine(days_ago=1), machine(days_ago=16)))
    assert out["transformedResponse"][COVERAGE] == 50


@pytest.mark.parametrize("loader", RUNNERS)
@pytest.mark.parametrize("body", NO_EVIDENCE)
def test_coverage_is_not_measured_without_evidence(loader, body):
    out = loader("requiredcoveragepercentage")(body())
    assert out["transformedResponse"][COVERAGE] is None
    assert collected(out) == "error"


# ---- epp_transform: isEPPEnabled, isEPPDeployed, isEDRDeployed, isEPPLoggingEnabled

@pytest.mark.parametrize("loader", RUNNERS)
def test_epp_passes_on_a_reporting_onboarded_fleet(loader):
    out = loader("epp_transform")(machines(machine(), machine("Onboarded"), machine("CanBeOnboarded")))
    for key in EPP_KEYS:
        assert out["transformedResponse"][key] is True, key
    assert collected(out) == "success"


@pytest.mark.parametrize("loader", RUNNERS)
def test_epp_fails_when_nothing_eligible_is_onboarded(loader):
    out = loader("epp_transform")(machines(machine("CanBeOnboarded"), machine("CanBeOnboarded")))
    for key in EPP_KEYS:
        assert out["transformedResponse"][key] is False, key
    assert collected(out) == "success"


@pytest.mark.parametrize("loader", RUNNERS)
def test_epp_fails_on_a_fleet_dark_for_180_days(loader):
    out = loader("epp_transform")(machines(machine(health="Inactive", days_ago=180)))
    for key in EPP_KEYS:
        assert out["transformedResponse"][key] is False, key
    assert collected(out) == "success"


@pytest.mark.parametrize("loader", RUNNERS)
def test_logging_fails_when_a_reporting_sensor_is_not_active(loader):
    out = loader("epp_transform")(machines(machine(), machine(health="ImpairedCommunication")))
    assert out["transformedResponse"]["isEPPDeployed"] is True
    assert out["transformedResponse"]["isEPPLoggingEnabled"] is False
    assert collected(out) == "success"


@pytest.mark.parametrize("loader", RUNNERS)
@pytest.mark.parametrize("body", NO_EVIDENCE)
def test_epp_is_not_measured_without_evidence(loader, body):
    out = loader("epp_transform")(body())
    for key in EPP_KEYS:
        assert out["transformedResponse"][key] is None, key
    assert collected(out) == "error"


@pytest.mark.parametrize("loader", RUNNERS)
def test_the_alert_list_is_named_as_the_wrong_source(loader):
    out = loader("epp_transform")(ALERTS_RETURNSPEC)
    assert "alert list" in out["additionalInfo"]["dataCollection"]["errors"][0]


# ---- checks no Defender method on this definition evidences

L2 = [
    pytest.param("ispatchmanagementenabled", ("isPatchManagementEnabled", "isPatchManagementValid"), id="patch"),
    pytest.param("isremovablemediacontrolled", ("isRemovableMediaControlled",), id="removable-media"),
    pytest.param("isbehavioralmonitoringvalid", ("isBehavioralMonitoringValid",), id="behavioral-monitoring"),
]


@pytest.mark.parametrize("loader", RUNNERS)
@pytest.mark.parametrize("name,keys", L2)
@pytest.mark.parametrize("body", [pytest.param(lambda: ALERTS, id="alert-list"),
                                  pytest.param(lambda: machines(machine()), id="machines")] + NO_EVIDENCE[2:])
def test_unevidenced_controls_are_never_answered(loader, name, keys, body):
    out = loader(name)(body())
    for key in keys:
        assert out["transformedResponse"][key] is None, key
    assert collected(out) == "error"


# ---- review findings on #1071

@pytest.mark.parametrize("loader", RUNNERS)
@pytest.mark.parametrize("fleet,dark", [(200, 1), (1000, 1)], ids=["199-of-200", "999-of-1000"])
def test_coverage_does_not_round_up_to_a_pass(loader, fleet, dark):
    """round() read 199 of 200 (99.5) and 999 of 1000 (99.9) as 100 and passed both, so a machine
    that was dark disappeared into the rounding and the line still said 100%."""
    records = [machine() for _ in range(fleet - dark)] + [machine(days_ago=180) for _ in range(dark)]
    out = loader("requiredcoveragepercentage")(machines(*records))
    assert out["transformedResponse"][COVERAGE] == 99
    assert collected(out) == "success"
    evaluation = out["additionalInfo"]["evaluation"]
    assert evaluation["passReasons"] == []
    assert "(99%)" in evaluation["failReasons"][0]


@pytest.mark.parametrize("loader", RUNNERS)
def test_a_full_fleet_still_passes_at_100(loader):
    out = loader("requiredcoveragepercentage")(machines(*[machine() for _ in range(200)]))
    assert out["transformedResponse"][COVERAGE] == 100
    assert out["additionalInfo"]["evaluation"]["failReasons"] == []
    assert collected(out) == "success"


@pytest.mark.parametrize("loader", RUNNERS)
def test_one_reporting_machine_without_healthStatus_is_not_measured(loader):
    """The guard only fired when NO reporting machine carried healthStatus. With a mixed inventory
    the record without it fell out of healthy and read isEPPLoggingEnabled False: a fail nobody
    measured."""
    blind = machine()
    del blind["healthStatus"]
    out = loader("epp_transform")(machines(machine(), machine(), blind))
    assert collected(out) == "error"
    for key in EPP_KEYS:
        assert out["transformedResponse"][key] is None, key
    assert "healthStatus" in out["additionalInfo"]["dataCollection"]["errors"][0]


@pytest.mark.parametrize("loader", RUNNERS)
def test_a_pass_on_a_sliver_of_the_fleet_reports_the_gap(loader):
    """One reporting machine passes the three deployment keys by design (the One-Click reading).
    The gap has to be visible beside the verdict, not only in the transformed response."""
    records = [machine()] + [machine("CanBeOnboarded") for _ in range(999)]
    out = loader("epp_transform")(machines(*records))
    assert out["transformedResponse"]["isEPPDeployed"] is True
    assert collected(out) == "success"
    findings = out["additionalInfo"]["evaluation"]["additionalFindings"]
    assert findings and "999 of 1000 eligible machines are not reporting" in findings[0]
    assert "requiredCoveragePercentage" in findings[0]


@pytest.mark.parametrize("loader", RUNNERS)
def test_a_fully_reporting_fleet_reports_no_gap(loader):
    out = loader("epp_transform")(machines(machine(), machine()))
    assert out["transformedResponse"]["isEPPDeployed"] is True
    assert out["additionalInfo"]["evaluation"]["additionalFindings"] == []
