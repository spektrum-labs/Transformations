"""Datto SaaS Protection checks on GET https://api.datto.com/v1/saas/domains.

The body copies the only published schema: the example output on
https://saasprotection.datto.com/help/M365/Content/Other_Administrative_Tasks/using-rest-api-saas-protection.htm
(values synthetic; no customer has connected yet). Each file runs in the Token-Service sandbox replica
(tools/restricted_sandbox.py) when RestrictedPython is installed, else as plain Python. Each check has a passing
body, a flip that must fail, and the fail-closed battery.
"""
import copy
import importlib.util
import json
import pathlib

import pytest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]

try:
    import RestrictedPython  # noqa: F401
    spec = importlib.util.spec_from_file_location("restricted_sandbox_datto_saas", ROOT / "tools" / "restricted_sandbox.py")
    sandbox = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sandbox)
    load_code = sandbox.load
except ImportError:
    def load_code(code, filename):
        ns = {"__name__": "datto_saas_" + filename}
        exec(compile(code, filename, "exec"), ns)
        return ns


def run(key, body):
    return load_code((HERE / (key.lower() + ".py")).read_text(), key)["transform"](body)[key]


def domain(i=0, active=89, recent=71, retention="ICR", seats=15, sub="Classic:1234566", org=145):
    return {"backupStats": {"activeServicesCount": active, "activeServicesWithRecentBackupCount": recent,
                            "backupPercentage": round(recent * 100.0 / active, 2) if active else 0},
            "domain": "example%d.com" % i, "saasCustomerId": 5000 + i, "saasCustomerName": "Example %d" % i,
            "organizationId": org, "organizationName": "Example Org", "seatsUsed": seats, "productType": "Office365",
            "externalSubscriptionId": sub, "retentionType": retention}


GOOD = [domain(0), domain(1, active=10, recent=10)]
FAIL_CLOSED = [{}, None, "{}", "", "[]", [], {"error": True, "statusCode": 401, "message": "Unauthorized"},
               {"error": {"type": "authentication_error"}}, {"hello": "world"}, [{"hello": "world"}]]
KEYS = ["backupSuccessRatePercentage", "isBackupEnabled", "confirmedLicensePurchased", "isDeletionRetentionPeriodEnforced"]


@pytest.mark.parametrize("key", KEYS)
@pytest.mark.parametrize("body", FAIL_CLOSED, ids=range(len(FAIL_CLOSED)))
def test_fail_closed(key, body):
    assert run(key, copy.deepcopy(body)) in (None, False)


@pytest.mark.parametrize("key", KEYS)
def test_two_organizations_refused(key):
    assert run(key, [domain(0), domain(1, org=999)]) in (None, False)


@pytest.mark.parametrize("wrap", [lambda b: b, json.dumps, lambda b: {"response": b}, lambda b: {"result": b},
                                  lambda b: {"apiResponse": {"data": b}}])
def test_wrappers(wrap):
    assert run("isBackupEnabled", wrap(copy.deepcopy(GOOD))) is True


def test_success_rate():
    assert run("backupSuccessRatePercentage", GOOD) == round(81 * 100.0 / 99, 2)
    assert run("backupSuccessRatePercentage", [domain(0, active=10, recent=10)]) == 100.0
    assert run("backupSuccessRatePercentage", [domain(0, active=0, recent=0)]) is None
    assert run("backupSuccessRatePercentage", [domain(0, active=5, recent=9)]) is None
    bad = copy.deepcopy(GOOD); del bad[1]["backupStats"]
    assert run("backupSuccessRatePercentage", bad) is None


def test_backup_enabled():
    assert run("isBackupEnabled", GOOD) is True
    assert run("isBackupEnabled", [domain(0), domain(1, recent=0)]) is False
    assert run("isBackupEnabled", [domain(0, active=0, recent=0)]) is False
    bad = copy.deepcopy(GOOD); bad[0]["backupStats"] = None
    assert run("isBackupEnabled", bad) is False


def test_license():
    assert run("confirmedLicensePurchased", GOOD) is True
    assert run("confirmedLicensePurchased", [domain(0), domain(1, seats=0)]) is False
    assert run("confirmedLicensePurchased", [domain(0, sub="")]) is False
    assert run("confirmedLicensePurchased", [domain(0, sub=None)]) is False


def test_retention():
    assert run("isDeletionRetentionPeriodEnforced", GOOD) is True
    assert run("isDeletionRetentionPeriodEnforced", [domain(0), domain(1, retention="TBR")]) is None
    assert run("isDeletionRetentionPeriodEnforced", [domain(0, retention="weird")]) is False
    assert run("isDeletionRetentionPeriodEnforced", [domain(0, retention=None)]) is False
