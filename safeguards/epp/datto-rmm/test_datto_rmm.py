"""Datto RMM (GET /api/v2/site/{siteUid}/devices), one client site per evaluation.

Three whole-number percentages; the pass bar lives in the requirement:
  requiredCoveragePercentage  devices whose antivirus is detected / devices judged
  isEPPConfigured             devices RunningAndUpToDate / devices with antivirus detected (FF-04)
  patchCompliancePercentage   devices FullyPatched / devices judged
Devices judged: deviceClass "device", not deleted, lastSeen within 15 days of the newest
lastSeen (endpoint rules 2026-09-29). No device judged, a truncated list, or a body that is
not a device page is not evaluated (dataCollection error, no value). Field names and enums are
from the Datto RMM API 2.0.0 OpenAPI document (Device, Antivirus, PatchManagement, DevicesPage).
Synthetic bodies only; no customer data.
"""
import copy
import importlib.util
import pathlib
from datetime import datetime, timedelta, timezone

import pytest

HERE = pathlib.Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location("datto_rmm_" + name, HERE / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def iso(days_ago):
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def device(av="RunningAndUpToDate", patch="FullyPatched", seen=0, cls="device", deleted=False, site="s-1"):
    return {"uid": f"d-{av}-{patch}-{seen}", "siteUid": site, "hostname": "h", "deviceClass": cls,
            "deleted": deleted, "lastSeen": iso(seen),
            "antivirus": {"antivirusProduct": "Datto AV", "antivirusStatus": av},
            "patchManagement": {"patchStatus": patch}}


def page(devices, **details):
    return {"pageDetails": {"count": len(devices), "totalCount": len(devices), "nextPageUrl": None, **details},
            "devices": devices}


def run(name, body):
    out = load(name).transform({"data": copy.deepcopy(body), "validation": {"status": "passed", "errors": [], "warnings": []}})
    return out["transformedResponse"].get(name), out["additionalInfo"]["dataCollection"]["status"]


FLEET = [
    device(),
    device(av="RunningAndNotUpToDate", patch="ApprovedPending"),
    device(av="NotRunning", patch="NoPolicy"),
    device(av="NotDetected", patch="InstallError"),
]


def test_coverage_counts_detected_antivirus_over_devices_judged():
    assert run("requiredCoveragePercentage", page(FLEET)) == (75, "success")


def test_configured_counts_running_and_up_to_date_over_protected():
    assert run("isEPPConfigured", page(FLEET)) == (33, "success")


def test_patch_compliance_counts_fully_patched_over_devices_judged():
    assert run("patchCompliancePercentage", page(FLEET)) == (25, "success")


@pytest.mark.parametrize("name", ["requiredCoveragePercentage", "isEPPConfigured", "patchCompliancePercentage"])
def test_all_healthy_is_100(name):
    assert run(name, page([device(), device()])) == (100, "success")


@pytest.mark.parametrize("name", ["requiredCoveragePercentage", "isEPPConfigured", "patchCompliancePercentage"])
def test_stale_printers_and_deleted_devices_are_left_out(name):
    fleet = [device(), device(av="NotDetected", patch="NoPolicy", seen=30),
             device(av="NotDetected", patch="NoPolicy", cls="printer"),
             device(av="NotDetected", patch="NoPolicy", deleted=True)]
    assert run(name, page(fleet)) == (100, "success")


@pytest.mark.parametrize("name", ["requiredCoveragePercentage", "isEPPConfigured", "patchCompliancePercentage"])
@pytest.mark.parametrize("body", [{}, None, [], "", {"devices": []}, {"error": "Unauthorized"},
                                  {"pageDetails": {"count": 0}, "devices": []},
                                  page([device()], truncated=True, scannedCount=1)])
def test_no_evidence_is_not_evaluated(name, body):
    value, status = run(name, body)
    assert value is None and status == "error"


def test_no_protected_device_leaves_configured_not_evaluated_but_coverage_zero():
    fleet = [device(av="NotDetected"), device(av="NotDetected")]
    assert run("requiredCoveragePercentage", page(fleet)) == (0, "success")
    assert run("isEPPConfigured", page(fleet)) == (None, "error")


def test_dark_fleet_is_all_stale_and_not_evaluated():
    assert run("requiredCoveragePercentage", page([device(seen=40), device(seen=45)])) == (None, "error")
