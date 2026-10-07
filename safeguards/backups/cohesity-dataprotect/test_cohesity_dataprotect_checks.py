"""Cohesity DataProtect (Helios v2 MCM) checks. Bodies follow the published OpenAPI shapes (GetMcmProtectionGroups
with includeLastRunInfo, GetHeliosPolicies, GetMfaPreferences, GetIdps) with synthetic values; no customer has
connected yet. Runs in the Token-Service sandbox replica when RestrictedPython is installed, else plain Python.
Each check has a pass, a flip that must fail, and the fail-closed battery."""
import copy
import importlib.util
import json
import pathlib
import time

import pytest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]
try:
    import RestrictedPython  # noqa: F401
    spec = importlib.util.spec_from_file_location("restricted_sandbox_cohesity", ROOT / "tools" / "restricted_sandbox.py")
    sandbox = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sandbox)
    load_code = sandbox.load
except ImportError:
    def load_code(code, filename):
        ns = {"__name__": "cohesity_" + filename}
        exec(compile(code, filename, "exec"), ns)
        return ns


def run(key, body):
    return load_code((HERE / (key.lower() + ".py")).read_text(), key)["transform"](body)[key]


NOW = int(time.time() * 1000000)
DAY = 24 * 3600 * 1000000


def group(i, status="Succeeded", sla=False, age_days=1, policy="p1", **flags):
    g = {"id": "1:2:%d" % i, "name": "pg%d" % i, "policyId": policy, "isActive": True, "isPaused": False, "isDeleted": False,
         "environment": "kVMware",
         "lastRun": {"id": "r%d" % i, "localBackupInfo": {"status": status, "isSlaViolated": sla, "runType": "kRegular",
                                                           "startTimeUsecs": NOW - age_days * DAY, "endTimeUsecs": NOW - age_days * DAY + 60000000}}}
    g.update(flags)
    return g


def policy(pid="p1", mode="Compliance", duration=30, inc_unit="Hours", full_unit=None):
    reg = {"retention": {"unit": "Days", "duration": 30}}
    if mode:
        reg["retention"]["dataLockConfig"] = {"mode": mode, "unit": "Days", "duration": duration}
    if inc_unit:
        reg["incremental"] = {"schedule": {"unit": inc_unit, "hourSchedule": {"frequency": 4}}}
    if full_unit:
        reg["full"] = {"schedule": {"unit": full_unit}}
    return {"id": pid, "name": "policy-" + pid, "backupPolicy": {"regular": reg}}


GROUPS = {"protectionGroups": [group(0), group(1), group(2, status="Failed", sla=True)]}
POSTURE = dict(GROUPS, policies=[policy()])
MFA = {"deploymentType": "HeliosSaas", "heliosSaasConfig": {"mfaStatus": "OptIn"}}
IDPS = {"idps": [{"id": 1, "name": "Okta", "domain": "corp", "isEnabled": True}]}
FAIL_CLOSED = [{}, None, "{}", "", {"error": True, "statusCode": 401}, {"errorCode": "KStatusUnauthorized", "message": "x"},
               {"hello": "world"}, []]
ALL = ["isBackupEnabled", "failedBackupJobsCount", "backupSuccessRatePercentage", "backupSlaComplianceRatePercentage",
       "staleProtectionJobsCount", "isBackupImmutable", "isDataLockComplianceModeEnabled", "isBackupTypesScheduled",
       "isMFAEnforcedForUsers", "isSSOEnabled"]


@pytest.mark.parametrize("key", ALL)
@pytest.mark.parametrize("body", FAIL_CLOSED, ids=range(len(FAIL_CLOSED)))
def test_fail_closed(key, body):
    assert run(key, copy.deepcopy(body)) in (None, False)


def test_groups():
    assert run("isBackupEnabled", GROUPS) is True
    assert run("isBackupEnabled", {"protectionGroups": [group(0, status="Failed"), group(1, isPaused=True)]}) is False
    assert run("isBackupEnabled", {"response": json.loads(json.dumps(GROUPS))}) is True
    assert run("failedBackupJobsCount", GROUPS) == 1
    assert run("failedBackupJobsCount", {"protectionGroups": [group(0), group(1)]}) == 0
    assert run("failedBackupJobsCount", {"protectionGroups": [group(0), {"name": "x", "isActive": True}]}) is None
    assert run("failedBackupJobsCount", dict(GROUPS, paginationCookie="abc")) is None
    assert run("failedBackupJobsCount", {"protectionGroups": []}) is None
    assert run("backupSuccessRatePercentage", GROUPS) == round(200 / 3.0, 2)
    assert run("backupSuccessRatePercentage", {"protectionGroups": [group(0, status="Running")]}) is None
    assert run("backupSlaComplianceRatePercentage", GROUPS) == round(200 / 3.0, 2)
    assert run("backupSlaComplianceRatePercentage", {"protectionGroups": [group(0, sla=None)]}) is None
    assert run("staleProtectionJobsCount", GROUPS) == 1
    assert run("staleProtectionJobsCount", {"protectionGroups": [group(0), group(1, age_days=9)]}) == 1
    assert run("staleProtectionJobsCount", {"protectionGroups": [group(0), group(1, isDeleted=True, status="Failed")]}) == 0


def test_policies():
    assert run("isBackupImmutable", POSTURE) is True
    assert run("isBackupImmutable", dict(GROUPS, policies=[policy(mode="Administrative")])) is True
    assert run("isBackupImmutable", dict(GROUPS, policies=[policy(mode=None)])) is False
    assert run("isBackupImmutable", dict(GROUPS, policies=[policy(duration=0)])) is False
    assert run("isBackupImmutable", dict(GROUPS, policies=[policy("other")])) is False
    assert run("isBackupImmutable", {"protectionGroups": [group(0), group(1, policy="p2")], "policies": [policy(), policy("p2", mode=None)]}) is False
    assert run("isDataLockComplianceModeEnabled", POSTURE) is True
    assert run("isDataLockComplianceModeEnabled", dict(GROUPS, policies=[policy(mode="Administrative")])) is False
    assert run("isBackupTypesScheduled", POSTURE) is True
    assert run("isBackupTypesScheduled", dict(GROUPS, policies=[policy(inc_unit=None, full_unit="Days")])) is True
    assert run("isBackupTypesScheduled", dict(GROUPS, policies=[policy(inc_unit=None, full_unit="ProtectOnce")])) is False
    assert run("isBackupTypesScheduled", dict(GROUPS, policies=[policy(inc_unit=None)])) is False
    assert run("isBackupTypesScheduled", {"protectionGroups": [], "policies": [policy()]}) is False


def test_mfa_sso():
    assert run("isMFAEnforcedForUsers", MFA) is True
    assert run("isMFAEnforcedForUsers", {"deploymentType": "HeliosSaas", "heliosSaasConfig": {"mfaStatus": "OptOut"}}) is False
    assert run("isMFAEnforcedForUsers", {"deploymentType": "HeliosOnPrem", "heliosOnPremConfig": {"mfa": True}}) is True
    assert run("isMFAEnforcedForUsers", {"deploymentType": "HeliosOnPrem", "heliosOnPremConfig": {"mfa": False}}) is False
    assert run("isSSOEnabled", IDPS) is True
    assert run("isSSOEnabled", {"idps": [{"name": "Okta", "isEnabled": False}]}) is False
    assert run("isSSOEnabled", {"idps": []}) is False
