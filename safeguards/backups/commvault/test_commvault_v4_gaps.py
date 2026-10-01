"""Commvault isBackupImmutable / isSAMLEnforced / isBackupLoggingEnabled (_v4 files).

Bodies are shaped after Commvault's public docs only: the V4 OpenAPI 3 document
(github.com/Commvault/CVPowershellSDKV2, OpenAPI3.yaml) and the public Python SDK
(github.com/Commvault/cvpysdk: storage_pool.py, eventviewer.py). Real verdicts on complete
reads; None (not False) on empty, partial, error and unrelated bodies.
"""
import importlib.util
import os
import time

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name):
    spec = importlib.util.spec_from_file_location("commvault_v4_" + name, os.path.join(HERE, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def value(file, key, payload):
    return load(file)(payload)["transformedResponse"][key]


def wrap(inner):
    return {"data": {"apiResponse": inner}, "validation": {"status": "skipped", "errors": [], "warnings": []}}


NO_EVIDENCE = [{}, "", None, {"status": 401, "message": "Unauthorized"}, {"error": "invalid_token"},
               {"errorCode": 5, "errorMessage": "Access denied"}, {"foo": "bar"},
               "<html><body>Command Center</body></html>"]


# ---- isBackupImmutable ------------------------------------------------------------------------

def pool(pid, name, worm_flag=0, is_worm=False, worm_copy=0):
    return {"storagePoolDetails": {
        "storagePoolEntity": {"storagePoolId": pid, "storagePoolName": name},
        "isWormStorage": is_worm,
        "copyInfo": {"wormStorageFlag": worm_flag, "copyFlags": {"wormCopy": worm_copy}}}}


def pools(details):
    listed = [{"storagePoolEntity": {"storagePoolId": d["storagePoolDetails"]["storagePoolEntity"]["storagePoolId"],
                                     "storagePoolName": d["storagePoolDetails"]["storagePoolEntity"]["storagePoolName"]}}
              for d in details]
    return wrap({"storagePoolList": listed, "poolDetails": details})


IMM = ("isbackupimmutable_v4", "isBackupImmutable")


def test_immutable_when_a_pool_is_locked():
    assert value(*IMM, pools([pool(1, "Primary"), pool(2, "AirGap", worm_flag=2)])) is True
    assert value(*IMM, pools([pool(1, "Primary", worm_copy=1)])) is True
    assert value(*IMM, pools([pool(1, "Primary", is_worm=True)])) is True


def test_not_immutable_when_no_pool_is_locked():
    assert value(*IMM, pools([pool(1, "Primary"), pool(2, "Cloud")])) is False


def test_immutable_none_on_partial_or_empty():
    full = pools([pool(1, "Primary", worm_flag=2), pool(2, "Cloud")])
    full["data"]["apiResponse"]["poolDetails"] = full["data"]["apiResponse"]["poolDetails"][:1]
    assert value(*IMM, full) is None
    assert value(*IMM, pools([])) is None
    no_fields = pools([{"storagePoolDetails": {"storagePoolEntity": {"storagePoolId": 1, "storagePoolName": "x"}}}])
    assert value(*IMM, no_fields) is None


@pytest.mark.parametrize("body", NO_EVIDENCE)
def test_immutable_none_on_no_evidence(body):
    assert value(*IMM, body) is None


# ---- isSAMLEnforced ---------------------------------------------------------------------------

def idp(name, kind="SAML", configured=True):
    return {"id": 1, "name": name, "type": kind, "samlType": "AZURE", "configured": configured}


def app(name, enabled=True, suffixes=None, groups=None):
    return {"name": name, "enabled": enabled, "autoCreateUser": True,
            "associations": {"emailSuffixes": suffixes or [], "domains": [], "companies": [], "userGroups": groups or []}}


SAML = ("issamlenforced_v4", "isSAMLEnforced")


def test_saml_enforced_when_enabled_and_associated():
    assert value(*SAML, wrap({"identityServers": [idp("EntraID")], "samlApps": [app("EntraID", suffixes=["example.com"])]})) is True
    assert value(*SAML, wrap({"identityServers": [idp("Okta")], "samlApps": [app("Okta", groups=[{"id": 3, "name": "Admins"}])]})) is True


def test_saml_not_enforced():
    assert value(*SAML, wrap({"identityServers": [idp("EntraID")], "samlApps": [app("EntraID", enabled=False, suffixes=["example.com"])]})) is False
    assert value(*SAML, wrap({"identityServers": [idp("EntraID")], "samlApps": [app("EntraID")]})) is False
    assert value(*SAML, wrap({"identityServers": [], "samlApps": []})) is False


def test_saml_none_on_partial():
    assert value(*SAML, wrap({"identityServers": [idp("A"), idp("B")], "samlApps": [app("A", suffixes=["x.com"])]})) is None
    assert value(*SAML, wrap({"identityServers": [idp("A")]})) is None


@pytest.mark.parametrize("body", NO_EVIDENCE)
def test_saml_none_on_no_evidence(body):
    assert value(*SAML, body) is None


# ---- isBackupLoggingEnabled -------------------------------------------------------------------

def event(i, age_days):
    return {"id": i, "eventCode": "318769020", "timeSource": int(time.time() - age_days * 86400),
            "severity": 3, "jobId": 1000 + i, "subsystem": "JobManager", "description": "Backup job completed"}


LOG = ("isbackuploggingenabled_v4", "isBackupLoggingEnabled")


def test_logging_enabled_with_recent_events():
    assert value(*LOG, wrap({"commservEvents": [event(1, 0.1), event(2, 30)]})) is True


def test_logging_stopped_when_newest_event_is_old():
    assert value(*LOG, wrap({"commservEvents": [event(1, 20), event(2, 40)]})) is False


def test_logging_none_on_empty_or_undated():
    assert value(*LOG, wrap({"commservEvents": []})) is None
    assert value(*LOG, wrap({"commservEvents": [{"id": 1, "eventCode": "1"}]})) is None


@pytest.mark.parametrize("body", NO_EVIDENCE)
def test_logging_none_on_no_evidence(body):
    assert value(*LOG, body) is None
