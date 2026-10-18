"""Cisco Meraki MX SAML, lockout and two-factor checks: a body that proves nothing is Not evaluated.

Token-Service grades a None criterion as FAILED unless additionalInfo.dataCollection.status is
"error", so each transform must answer None AND carry a dataCollection error when the organization
SAML or loginSecurity body is empty, a vendor error body, or lacks the field. An explicit false
from Meraki is a real fail. Synthetic data only.
"""
import importlib.util
import os

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name):
    spec = importlib.util.spec_from_file_location("meraki_login_ne_" + name, os.path.join(HERE, name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


SSO = load("isSSOEnabled")
LOCK = load("adminLockoutThresholdCount")
TFA = load("isTwoFactorAuthEnforced")
IDLE = load("isAdminIdleTimeoutEnforced")

EMPTY_BODIES = [
    {},
    {"vendorErrorAsResponse": {"status": 403, "errors": ["Forbidden"]}},
    {"errors": ["API key invalid"]},
    {"enabled": None},
]


def collection(out):
    return out["additionalInfo"]["dataCollection"]


@pytest.mark.parametrize("body", EMPTY_BODIES)
def test_sso_unusable_body_is_none_with_collection_error(body):
    out = SSO.transform(body)
    assert out["transformedResponse"]["isSSOEnabled"] is None
    assert collection(out)["status"] == "error" and collection(out)["errors"]


@pytest.mark.parametrize("body", [{}, {"vendorErrorAsResponse": {"status": 403}}, {"enforceAccountLockout": None}])
def test_lockout_unusable_body_is_none_with_collection_error(body):
    out = LOCK.transform(body)
    assert out["transformedResponse"]["adminLockoutThresholdCount"] is None
    assert collection(out)["status"] == "error" and collection(out)["errors"]


@pytest.mark.parametrize("body", [{}, {"vendorErrorAsResponse": {"status": 403}}, {"enforceTwoFactorAuth": None}])
def test_two_factor_unusable_body_is_none_with_collection_error(body):
    out = TFA.transform(body)
    assert out["transformedResponse"]["isTwoFactorAuthEnforced"] is None
    assert collection(out)["status"] == "error" and collection(out)["errors"]


def test_explicit_false_is_a_real_fail():
    out = SSO.transform({"enabled": False})
    assert out["transformedResponse"]["isSSOEnabled"] is False
    assert collection(out)["status"] == "success"
    # Lockout switched off: effective threshold is 0 even when a stale attempt count is stored,
    # so a bundle range check (1 to 5) cannot pass on it.
    out = LOCK.transform({"enforceAccountLockout": False, "accountLockoutAttempts": 5})
    assert out["transformedResponse"]["adminLockoutThresholdCount"] == 0
    assert out["transformedResponse"]["enforceAccountLockout"] is False
    assert collection(out)["status"] == "success"
    out = TFA.transform({"enforceTwoFactorAuth": False})
    assert out["transformedResponse"]["isTwoFactorAuthEnforced"] is False
    assert collection(out)["status"] == "success"


def test_explicit_true_passes():
    assert SSO.transform({"enabled": True})["transformedResponse"]["isSSOEnabled"] is True
    out = LOCK.transform({"enforceAccountLockout": True, "accountLockoutAttempts": 5})
    assert out["transformedResponse"]["adminLockoutThresholdCount"] == 5
    assert TFA.transform({"enforceTwoFactorAuth": True})["transformedResponse"]["isTwoFactorAuthEnforced"] is True


@pytest.mark.parametrize("body", [{}, {"vendorErrorAsResponse": {"status": 403}}, {"enforceIdleTimeout": None}])
def test_idle_timeout_unusable_body_is_none_with_collection_error(body):
    out = IDLE.transform(body)
    assert out["transformedResponse"]["isAdminIdleTimeoutEnforced"] is None
    assert collection(out)["status"] == "error" and collection(out)["errors"]


def test_idle_timeout_explicit_values():
    out = IDLE.transform({"enforceIdleTimeout": False, "idleTimeoutMinutes": []})
    assert out["transformedResponse"]["isAdminIdleTimeoutEnforced"] is False
    assert collection(out)["status"] == "success"
    out = IDLE.transform({"enforceIdleTimeout": True, "idleTimeoutMinutes": 15})
    assert out["transformedResponse"]["isAdminIdleTimeoutEnforced"] is True


def test_lockout_unbounded_reports_zero():
    for body in ({"enforceAccountLockout": False, "accountLockoutAttempts": []},
                 {"enforceAccountLockout": True, "accountLockoutAttempts": []}):
        out = LOCK.transform(body)
        assert out["transformedResponse"]["adminLockoutThresholdCount"] == 0
