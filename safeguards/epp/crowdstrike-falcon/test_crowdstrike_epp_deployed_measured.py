"""CrowdStrike Falcon isEPPDeployed: a measured share of reporting hosts, not a literal True.

Before 2026-10-07 isEPPDeployed.py answered `"isEPPDeployed": True` for any body carrying one host ID or
host record. Replayed against the real captured bodies in fixtures/, it said True for a fleet whose every
host had been dark for 90 days and for one 100-record page of a much larger tenant.

Now a host counts as deployed when it has an agent_version, is not in Reduced Functionality Mode and
checked in within ACTIVE_WINDOW_DAYS; mobile hosts are left out; isEPPDeployed holds when that share
reaches DEPLOYED_THRESHOLD. A host-ID list, a partial read and an all-mobile read are Unevaluated.

All host data built here is synthetic ("estate E"); the real fixtures are only read, never copied."""
import importlib.util
import json
import pathlib
from datetime import datetime, timedelta

import pytest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def load():
    spec = importlib.util.spec_from_file_location("cs_falcon_epp_deployed_measured", HERE / "isEPPDeployed.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


EPP = load()


def ago(days=0, hours=1):
    return (datetime.utcnow() - timedelta(days=days, hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")


def host(n, last_seen=None, rfm="no", agent_version="7.40.21309.0", product="Workstation", platform="Windows"):
    record = {"device_id": "estate-e-dev-%04d" % n, "platform_name": platform, "product_type_desc": product,
              "status": "normal", "reduced_functionality_mode": rfm, "last_seen": last_seen or ago()}
    if agent_version is not None:
        record["agent_version"] = agent_version
    return record


def body(records, **pagination):
    page = {"offset": "", "limit": 5000, "total": len(records)}
    page.update(pagination)
    return {"meta": {"pagination": page, "powered_by": "device-api"}, "resources": records, "errors": []}


def run(payload):
    out = EPP.transform(payload)
    return out["transformedResponse"], out["additionalInfo"]


def assert_measured(payload, expected):
    result, info = run(payload)
    assert result["isEPPDeployed"] is expected, result
    assert info["dataCollection"] == {"status": "success", "errors": []}
    return result, info


def assert_unevaluated(payload, reason=None):
    result, info = run(payload)
    assert result == {"isEPPDeployed": None, "sensorDeploymentPercentage": None, "totalDevices": None,
                      "reportingDevices": None}
    assert info["dataCollection"]["status"] == "error"
    assert info["evaluation"]["failReasons"] == info["dataCollection"]["errors"]
    if reason:
        assert reason in info["dataCollection"]["errors"][0], info["dataCollection"]["errors"][0]
    return info


# ---------------------------------------------------------------- the threshold

def test_threshold_is_explicit():
    assert EPP.DEPLOYED_THRESHOLD == 95.0
    assert EPP.ACTIVE_WINDOW_DAYS == 15


def test_every_host_reporting_passes():
    result, info = assert_measured(body([host(i) for i in range(20)]), True)
    assert result == {"isEPPDeployed": True, "sensorDeploymentPercentage": 100.0, "totalDevices": 20,
                      "reportingDevices": 20}
    assert "at or above the 95.0% bar" in info["evaluation"]["passReasons"][0]


def test_exactly_at_the_bar_passes_and_one_below_fails():
    at_bar = [host(i) for i in range(19)] + [host(19, last_seen=ago(days=40))]
    result, _ = assert_measured(body(at_bar), True)
    assert result["sensorDeploymentPercentage"] == 95.0
    below = [host(i) for i in range(18)] + [host(18, last_seen=ago(days=40)), host(19, last_seen=ago(days=40))]
    result, info = assert_measured(body(below), False)
    assert result["sensorDeploymentPercentage"] == 90.0
    assert "below the 95.0% bar" in info["evaluation"]["failReasons"][0]
    assert info["evaluation"]["recommendations"]


def test_one_reporting_host_of_many_fails():
    # "at least one host exists" was the old pass condition
    records = [host(0)] + [host(i, last_seen=ago(days=30)) for i in range(1, 50)]
    result, _ = assert_measured(body(records), False)
    assert result["reportingDevices"] == 1


# ---------------------------------------------------------------- what counts as deployed

def test_a_fleet_dark_for_90_days_fails():
    records = [host(i, last_seen=ago(days=90)) for i in range(25)]
    result, info = assert_measured(body(records), False)
    assert result["sensorDeploymentPercentage"] == 0.0
    assert info["transformation"]["inputSummary"]["notReportingDevices"] == 25


@pytest.mark.parametrize("flip", ["rfm_yes", "rfm_true_bool", "no_agent_version", "blank_agent_version",
                                  "no_last_seen", "unreadable_last_seen"])
def test_hosts_that_do_not_count(flip):
    if flip == "rfm_yes":
        bad = host(0, rfm="Yes")
    elif flip == "rfm_true_bool":
        bad = host(0, rfm=True)
    elif flip == "no_agent_version":
        bad = host(0, agent_version=None)
    elif flip == "blank_agent_version":
        bad = host(0, agent_version="  ")
    elif flip == "no_last_seen":
        bad = host(0)
        del bad["last_seen"]
    else:
        bad = host(0, last_seen="last tuesday")
    result, _ = assert_measured(body([bad] + [host(i) for i in range(1, 10)]), False)
    assert result["reportingDevices"] == 9, flip


def test_containment_status_does_not_matter():
    records = [host(i) for i in range(10)]
    records[0]["status"] = "contained"
    assert_measured(body(records), True)


def test_mobile_hosts_are_left_out_of_the_share():
    records = [host(i) for i in range(10)] + [host(10, product="Mobile", last_seen=ago(days=60)),
                                               host(11, platform="iOS", agent_version=None)]
    result, info = assert_measured(body(records), True)
    assert result["totalDevices"] == 10
    assert info["transformation"]["inputSummary"]["mobileSkipped"] == 2


def test_only_mobile_hosts_is_unevaluated():
    assert_unevaluated(body([host(0, product="Mobile"), host(1, platform="Android")]), "mobile")


def test_unknown_rfm_that_decides_the_verdict_is_unevaluated():
    records = [host(i) for i in range(18)] + [host(18, rfm="maybe"), host(19, rfm="maybe")]
    assert_unevaluated(body(records), "cannot be decided")


def test_unknown_rfm_that_cannot_decide_the_verdict_is_measured():
    records = [host(i) for i in range(15)] + [host(15, rfm="maybe")] + [host(i, last_seen=ago(days=50))
                                                                          for i in range(16, 20)]
    result, info = assert_measured(body(records), False)
    assert info["transformation"]["inputSummary"]["rfmUnknown"] == 1


# ---------------------------------------------------------------- what is not measured

def test_host_id_list_is_unevaluated():
    ids = ["%032x" % (0xe0 + i) for i in range(30)]
    assert_unevaluated(body(ids), "not that its sensor is reporting")


@pytest.mark.parametrize("partial", [{"total": 900}, {"total": "900"}, {"next": "estate-e-next"},
                                     {"truncated": True}])
def test_partial_read_is_unevaluated_even_when_every_host_read_reports(partial):
    assert_unevaluated(body([host(i) for i in range(10)], **partial), "partial")


def test_platform_truncation_flag_is_unevaluated():
    assert_unevaluated(dict(body([host(i) for i in range(10)]), paginationTruncated=True), "partial")


@pytest.mark.parametrize("payload", [None, {}, body([]), {"errors": [{"code": 403, "message": "denied"}]},
                                     dict(body([host(0)]), errors=[{"code": 500, "message": "boom"}])])
def test_nothing_read_is_unevaluated(payload):
    assert_unevaluated(payload)


# ---------------------------------------------------------------- the real captured fixtures (read only)

def test_real_complete_host_list_is_measured_and_discriminates():
    real = json.loads((HERE / "fixtures" / "falcon_hosts_sensor_update_real_2026-09-25.json").read_text())
    result, info = assert_measured(real, False)
    assert 0 < result["sensorDeploymentPercentage"] < EPP.DEPLOYED_THRESHOLD
    assert info["transformation"]["inputSummary"]["notReportingDevices"] > 0
    for record in real["resources"]:
        record["last_seen"] = ago()
    assert_measured(real, True)
    for record in real["resources"]:
        record["last_seen"] = ago(days=90)
    result, _ = assert_measured(real, False)
    assert result["sensorDeploymentPercentage"] == 0.0


def test_real_partial_page_is_unevaluated():
    real = json.loads((HERE / "fixtures" / "xdr_devices_unpaged_real_2026-09-25.json").read_text())
    assert_unevaluated(real, "partial")


# ---------------------------------------------------------------- the production sandbox

def test_compiles_and_discriminates_in_the_restricted_sandbox():
    import sys
    sys.path.insert(0, str(ROOT / "tools"))
    try:
        import restricted_sandbox
    except ImportError:  # RestrictedPython not installed locally; CI's contract job compiles every file
        return
    epp = restricted_sandbox.load((HERE / "isEPPDeployed.py").read_text())["transform"]
    passing = epp(body([host(i) for i in range(10)]))
    failing = epp(body([host(i, last_seen=ago(days=90)) for i in range(10)]))
    nothing = epp(body(["%032x" % i for i in range(10)]))
    assert (passing["transformedResponse"]["isEPPDeployed"], passing["additionalInfo"]["dataCollection"]["status"]) == (True, "success")
    assert (failing["transformedResponse"]["isEPPDeployed"], failing["additionalInfo"]["dataCollection"]["status"]) == (False, "success")
    assert (nothing["transformedResponse"]["isEPPDeployed"], nothing["additionalInfo"]["dataCollection"]["status"]) == (None, "error")



# --- review findings on #1070 ----------------------------------------------------------------

def test_the_threshold_uses_the_exact_ratio_not_the_rounded_one():
    """18,999 of 20,000 is 94.995%, which rounds to 95.0. It must not pass."""
    records = [host(i, last_seen=ago(1)) for i in range(18999)]
    records += [host(20000 + i, last_seen=ago(90)) for i in range(1001)]
    assert_measured(body(records), False)


def test_a_list_mixing_host_records_and_bare_ids_is_not_measured():
    records = [host(1, last_seen=ago(1))] + ["a" * 32 for _ in range(99)]
    assert_unevaluated(body(records))
