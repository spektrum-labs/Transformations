"""Tests for isstrongauthrequired.py (Azure AD d9b6f27a): Microsoft Authenticator is not phishing-resistant (2 Oct 2026)."""
import importlib.util
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("isstrongauthrequired", Path(__file__).with_name("isstrongauthrequired.py"))
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


def policy(enabled):
    ids = ["Fido2", "MicrosoftAuthenticator", "Sms", "Email", "Voice", "SoftwareOath", "TemporaryAccessPass", "X509Certificate"]
    return {"authenticationMethodConfigurations": [{"id": i, "state": "enabled" if i in enabled else "disabled"} for i in ids]}


def out(enabled):
    return MOD.transform(policy(enabled))["transformedResponse"]


def test_authenticator_only_fails():
    # Trebron (2 Oct): Microsoft Authenticator and SMS only, passed until now.
    r = out(["MicrosoftAuthenticator", "Sms"])
    assert r["isStrongAuthRequired"] is False
    assert r["enabledStrongMethods"] == []
    assert "Microsoft Authenticator (push / phone sign-in)" in r["enabledWeakMethods"]


def test_fido2_with_phishable_methods_passes():
    # Thoma Bravo / LSC Comm shape: FIDO2 plus Authenticator, SMS, email OTP, OATH, voice.
    r = out(["Fido2", "MicrosoftAuthenticator", "Sms", "Email", "SoftwareOath", "Voice"])
    assert r["isStrongAuthRequired"] is True
    assert r["enabledStrongMethods"] == ["FIDO2 Security Key"]


def test_certificate_based_auth_passes():
    assert out(["X509Certificate"])["isStrongAuthRequired"] is True


def test_email_otp_only_fails():
    # Permasteelisa / Millar Western: email OTP only.
    r = out(["Email"])
    assert r["isStrongAuthRequired"] is False
    assert r["enabledWeakMethods"] == ["Email OTP"]


def test_temporary_access_pass_is_phishable():
    assert out(["TemporaryAccessPass"])["isStrongAuthRequired"] is False
