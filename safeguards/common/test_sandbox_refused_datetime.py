"""The nine transforms whose date logic never ran in production, run where production runs them.

`datetime.strftime()` imports `time`, `datetime.strptime()` imports `_strptime`, and `date.today()`
imports `time`, all inside CPython. Token-Service's import hook refuses both modules, so each call
raised ImportError in the sandbox. Most of these files caught it with `except Exception`, so the
transform "succeeded" with its date logic skipped: expired licences counted as active, ended campaigns
counted as running, the oldest phishing campaign reported instead of the newest. Every test runs the
file under tools/restricted_sandbox.py (the Token-Service replica) with a body that reaches the date
code, and asserts the verdict production now returns. tools/check_sandbox_compile.py keeps the class out.
"""
import importlib.util
import pathlib
from datetime import datetime, timedelta

import pytest

pytest.importorskip("RestrictedPython")

SAFEGUARDS = pathlib.Path(__file__).resolve().parents[1]
ROOT = SAFEGUARDS.parent
spec = importlib.util.spec_from_file_location("restricted_sandbox_datetime", ROOT / "tools" / "restricted_sandbox.py")
sandbox = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sandbox)

NOW = datetime.utcnow()
VALID = {"status": "valid", "errors": [], "warnings": []}


def run(rel, body):
    out = sandbox.load((SAFEGUARDS / rel).read_text(), rel)["transform"](body)
    return out.get("transformedResponse", out)


def ago(days, z="Z"):
    return (NOW - timedelta(days=days)).replace(microsecond=123000).isoformat(timespec="milliseconds") + z


def day(days):
    return (NOW - timedelta(days=days)).date().isoformat()


def test_threatdown_skips_an_expired_active_licence():
    rel = "epp/threatdown/confirmedlicensepurchased.py"
    expired = {"license_status": "active", "license_expires_at": "2020-01-01T00:00:00Z", "licensed_seats": 10}
    current = {"license_status": "active", "license_expires_at": day(-100) + "T00:00:00Z", "licensed_seats": 10}
    assert run(rel, {"data": {"product_license_info": [expired]}, "validation": VALID})["confirmedLicensePurchased"] is False
    assert run(rel, {"data": {"product_license_info": [current]}, "validation": VALID})["confirmedLicensePurchased"] is True


def test_knowbe4_click_rate_comes_from_the_newest_campaign():
    rel = "compliancemanagement/knowbe4/phishingclickrate.py"
    campaigns = [{"status": "Closed", "last_run": ago(40), "name": "old", "last_phish_prone_percentage": 30},
                 {"status": "Closed", "last_run": ago(3), "name": "new", "last_phish_prone_percentage": 7}]
    assert run(rel, {"data": {"campaigns": campaigns}, "validation": VALID})["phishingClickRate"] == "7"


def test_knowbe4_simulation_reads_the_last_run_date():
    rel = "compliancemanagement/knowbe4/phishingsimulationactive.py"
    out = run(rel, {"data": {"campaigns": [{"status": "Closed", "last_run": ago(10)}]}, "validation": VALID})
    assert out["latestRunDate"] not in ("N/A", None)


def test_kaseya_counts_each_device_once():
    rel = "epp/kaseya/vsa/ispatchmanagementenabled.py"
    devices = [{"patchPolicy": "p", "patchStatus": "current", "lastPatchDate": ago(3, z="")},
               {"patchPolicy": "p", "patchStatus": "missing", "lastPatchDate": ago(90, z="")}]
    out = run(rel, {"devices": devices})
    assert out["patchedDevices"] == 1
    assert out["isPatchManagementValid"] is False


def test_keeper_sees_a_dormant_enabled_user():
    rel = "iam/keeper/isdormantaccountsdisabled.py"
    out = run(rel, {"users": [{"last_login": ago(100), "active": True}, {"last_login": ago(2), "active": True}]})
    assert out["dormantUsers"] == 1
    assert out["isDormantAccountsDisabled"] is False


@pytest.mark.parametrize("expires, expected", [(day(-60), True), ("2020-01-01", False)])
def test_pingfederate_licence_expiry(expires, expected):
    rel = "mfa/pingfederate/confirmedlicensepurchased.py"
    out = run(rel, {"data": {"id": "L1", "expirationDate": expires}, "validation": VALID})
    assert out["confirmedLicensePurchased"] is expected


@pytest.mark.parametrize("rel, key, field, list_key", [
    ("training/ninjio/isphishingsimulationenabled.py", "isPhishingSimulationEnabled", "end_date", "campaigns"),
    ("training/ninjio/istrainingenabled.py", "isTrainingEnabled", "end", "simulations"),
])
def test_ninjio_ended_campaign_is_not_active(rel, key, field, list_key):
    ended = {"data": {list_key: [{"status": "active", field: "2020-01-01"}]}, "validation": VALID}
    running = {"data": {list_key: [{"status": "active", field: day(-10)}]}, "validation": VALID}
    assert run(rel, ended)[key] is False
    assert run(rel, running)[key] is True


def test_crashplan_counts_a_date_only_restore():
    rel = "backups/crashplan/isbackuptested.py"
    assert run(rel, {"restores": [{"doneDate": day(10), "status": "done"}]})["recentRestores"] == 1
    assert run(rel, {"restores": [{"doneDate": day(200), "status": "done"}]})["recentRestores"] == 0
