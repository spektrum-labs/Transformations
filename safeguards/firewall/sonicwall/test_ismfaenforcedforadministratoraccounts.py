import unittest

from conftest import envelope, fixture_envelope, group, load_module, user


FILENAME = "ismfaenforcedforadministratoraccounts.py"


def transformation():
    return load_module(FILENAME)


def test_empty_additional_administrator_population_passes_separately_from_builtin():
    result = transformation().transform(envelope())["transformedResponse"]
    assert result["isMFAEnforcedForAdministratorAccounts"] is True
    assert result["scoredAdministratorAccounts"] == 0
    assert result["compliantAdministratorAccounts"] == 0


def test_additional_administrators_require_effective_totp_not_email_otp():
    module = transformation()
    groups = [group("SonicWall Administrators", members=["totp-admin", "email-admin"])]
    response = module.transform(envelope([
        user("totp-admin", "totp"),
        user("email-admin", "email", email_address="admin@example.test"),
    ], groups))
    result = response["transformedResponse"]
    assert result["isMFAEnforcedForAdministratorAccounts"] is False
    assert result["scoredAdministratorAccounts"] == 2
    assert result["compliantAdministratorAccounts"] == 1
    assert result["noncompliantAdministratorAccounts"] == 1
    assert "totp-admin" not in str(response)
    assert "email-admin" not in str(response)


def test_nested_administrator_membership_and_inherited_totp_pass():
    module = transformation()
    groups = [
        group("delegates", members=["nested-admin"]),
        group("SonicWall Read-Only Admins", "totp", ["delegates"]),
    ]
    result = module.transform(envelope([user("nested-admin", "none", ["delegates"])], groups))["transformedResponse"]
    assert result["isMFAEnforcedForAdministratorAccounts"] is True
    assert result["compliantAdministratorAccounts"] == 1


def test_cycle_ambiguity_and_unknown_admin_evidence_fail_closed():
    module = transformation()
    cycle = envelope(
        [user("cycle-admin", "totp", ["cycle-a"])],
        [group("cycle-a", members=["cycle-b", "cycle-admin"]),
         group("cycle-b", members=["cycle-a", "SonicWall Administrators"]),
         group("SonicWall Administrators", members=["cycle-b"])],
    )
    cycle_response = module.transform(cycle)
    assert cycle_response["transformedResponse"]["isMFAEnforcedForAdministratorAccounts"] is False
    assert cycle_response["additionalInfo"]["validation"]["status"] == "failed"

    ambiguous = envelope(
        [user("same", "totp")],
        [group("same"), group("SonicWall Administrators", "totp", ["same"])],
    )
    ambiguity_response = module.transform(ambiguous)
    assert ambiguity_response["transformedResponse"]["isMFAEnforcedForAdministratorAccounts"] is False
    assert "group_membership_unresolved" in ambiguity_response["additionalInfo"]["validation"]["errors"]

    unknown = envelope([user("unknown-admin", "unknown", ["SonicWall Administrators"])],
                       [group("SonicWall Administrators", members=["unknown-admin"])])
    assert module.transform(unknown)["transformedResponse"]["isMFAEnforcedForAdministratorAccounts"] is False


def test_domain_and_expired_administrators_are_reported_but_unscored():
    module = transformation()
    groups = [group("Limited Administrators", "totp", ["expired-admin", "domain-admin"])]
    result = module.transform(envelope([
        user("expired-admin", "none", expired=True),
        user("domain-admin", "none", domain="example.test"),
    ], groups))["transformedResponse"]
    assert result["isMFAEnforcedForAdministratorAccounts"] is True
    assert result["expiredAdministratorAccounts"] == 1
    assert result["excludedDomainProxies"] == 1
    assert result["scoredAdministratorAccounts"] == 0


def test_supported_generation_fixtures_normalize_and_indeterminate_admins_fail_closed():
    module = transformation()
    for contract in ("gen6-combined", "gen6-split", "gen7-split"):
        response = module.transform(fixture_envelope(contract))
        assert response["transformedResponse"]["isMFAEnforcedForAdministratorAccounts"] is False
        assert response["additionalInfo"]["validation"]["status"] == "failed"
        assert "synthetic-" not in str(response)


def load_tests(loader, standard_tests, pattern):
    suite = unittest.TestSuite()
    for function_name in sorted(globals()):
        if function_name.startswith("test_"):
            suite.addTest(unittest.FunctionTestCase(globals()[function_name], description=function_name))
    return suite
