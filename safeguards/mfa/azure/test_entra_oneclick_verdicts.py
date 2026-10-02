"""Tests for entra_strongauth_methods.py and entra_ca_tenantwide_mfa.py (2026-09-29)."""
import importlib.util
from pathlib import Path


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


STRONG = load("entra_strongauth_methods")
CA = load("entra_ca_tenantwide_mfa")
NO_EVIDENCE = (None, {}, "", {"error": True, "message": "HTTP 403"}, {"error": {"code": "InvalidAuthenticationToken"}},
               {"value": []})


def methods(enabled, migration="migrationComplete", extra=()):
    ids = ["Fido2", "MicrosoftAuthenticator", "Sms", "Email", "Voice"]
    configs = [{"id": i, "state": "enabled" if i in enabled else "disabled"} for i in ids] + list(extra)
    return {"@odata.context": "https://graph.microsoft.com/v1.0/$metadata#authenticationMethodsPolicy",
            "policyMigrationState": migration, "authenticationMethodConfigurations": configs}


def strong(body):
    return STRONG.transform(body)["transformedResponse"]["isStrongAuthRequired"]


def test_strong_method_enabled_passes():
    assert strong(methods(["Fido2", "MicrosoftAuthenticator", "Sms"])) is True
    assert strong(methods(["Fido2"], "preMigration")) is True
    cba = {"id": "X509Certificate", "state": "enabled"}
    assert strong(methods([], extra=[cba])) is True


def test_microsoft_authenticator_alone_is_not_phishing_resistant():
    # J.J. 2 Oct 2026 02:35 ET: push / phone sign-in is phishable. Crown, Flagstone Foods, Marcal, Packaging
    # Exchange, Thunder Bay, Trebron and US Farathane passed on Authenticator alone.
    assert strong(methods(["MicrosoftAuthenticator", "Sms"])) is False
    out = STRONG.transform(methods(["MicrosoftAuthenticator", "Email", "Sms", "Voice"]))
    assert out["transformedResponse"]["enabledStrongMethods"] == []
    assert "MicrosoftAuthenticator" in out["transformedResponse"]["enabledPhishableMethods"]
    assert "phishable" in out["additionalInfo"]["evaluation"]["failReasons"][0]
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"


def test_fido2_alongside_phishable_methods_still_passes():
    # The 14 tenants with FIDO2 enabled (e.g. Infraservices: Fido2, MicrosoftAuthenticator, TemporaryAccessPass).
    tap = {"id": "TemporaryAccessPass", "state": "enabled"}
    out = STRONG.transform(methods(["Fido2", "MicrosoftAuthenticator"], extra=[tap]))
    assert out["transformedResponse"]["isStrongAuthRequired"] is True
    assert out["transformedResponse"]["enabledStrongMethods"] == ["FIDO2 security key"]


def test_authenticator_only_during_migration_is_not_evaluated():
    assert strong(methods(["MicrosoftAuthenticator"], "preMigration")) is None


def test_no_strong_method_after_migration_fails():
    assert strong(methods(["Sms", "Email"])) is False


def test_no_strong_method_during_migration_or_with_external_method_is_not_evaluated():
    assert strong(methods(["Email"], "migrationInProgress")) is None
    duo = {"@odata.type": "#microsoft.graph.externalAuthenticationMethodConfiguration", "id": "bfa47a53",
           "displayName": "Cisco Duo", "state": "enabled"}
    assert strong(methods([], extra=[duo])) is None


def test_strong_auth_without_the_policy_is_not_evaluated():
    for body in NO_EVIDENCE + ({"authenticationMethodConfigurations": []}, {"value": [{"id": "u1"}]}):
        assert strong(body) is None


def policy(name, users=None, groups=None, roles=None, apps=("All",), grant=("mfa",), operator="OR", **conditions):
    cond = {"users": {"includeUsers": list(users or []), "includeGroups": list(groups or []), "includeRoles": list(roles or [])},
            "applications": {"includeApplications": list(apps)}, "clientAppTypes": ["all"]}
    cond.update(conditions)
    return {"displayName": name, "state": "enabled", "conditions": cond,
            "grantControls": {"operator": operator, "builtInControls": list(grant)}}


def ca(*policies):
    out = CA.transform({"@odata.context": "https://graph.microsoft.com/v1.0/$metadata#identity/conditionalAccess/policies",
                        "value": list(policies)})
    return out["transformedResponse"], out["additionalInfo"]["dataCollection"]["errors"]


def test_all_users_mfa_policy_passes_both_keys():
    result, errors = ca(policy("MFA all", users=["All"], locations={"includeLocations": ["All"], "excludeLocations": ["AllTrusted"]}))
    assert result["isRDPProtected"] is True and result["isMFARequiredForRemoteAccess"] is True and not errors


def test_block_guest_admin_and_risk_policies_do_not_pass():
    result, errors = ca(policy("Block legacy", users=["All"], grant=("block",), clientAppTypes=["exchangeActiveSync", "other"]),
                        policy("Guest MFA"), policy("Admin MFA", roles=["62e90394"]),
                        policy("Risky", groups=["g1"], signInRiskLevels=["high"]))
    assert result["isRDPProtected"] is False and result["isMFARequiredForRemoteAccess"] is False


def test_mfa_or_compliant_device_is_not_mfa():
    result, errors = ca(policy("MFA or device", users=["All"], grant=("mfa", "compliantDevice")))
    assert result["isMFARequiredForRemoteAccess"] is False


def test_group_scoped_or_platform_narrowed_policy_is_not_evaluated():
    result, errors = ca(policy("Groups", groups=["g1", "g2"]))
    assert result["isMFARequiredForRemoteAccess"] is None and errors
    result, errors = ca(policy("No phones", users=["All"], platforms={"includePlatforms": ["all"], "excludePlatforms": ["iOS"]}))
    assert result["isRDPProtected"] is None and errors


def test_trusted_only_location_policy_does_not_cover_remote_access():
    result, errors = ca(policy("Office only", users=["All"], locations={"includeLocations": ["AllTrusted"]}),
                        policy("Guest MFA"))
    assert result["isMFARequiredForRemoteAccess"] is not True


def test_no_enabled_policy_or_no_evidence_is_not_evaluated():
    disabled = dict(policy("Off", users=["All"]), state="disabled")
    result, errors = ca(disabled)
    assert result["isRDPProtected"] is None and errors
    for body in NO_EVIDENCE:
        out = CA.transform(body)["transformedResponse"]
        assert out["isRDPProtected"] is None and out["isMFARequiredForRemoteAccess"] is None


def test_pages_left_unread_is_not_evaluated():
    out = CA.transform({"@odata.context": "x", "@odata.nextLink": "https://graph.microsoft.com/next",
                        "value": [policy("MFA all", users=["All"])]})["transformedResponse"]
    assert out["isRDPProtected"] is None
