import unittest

from conftest import envelope, fixture_envelope, group, load_module, user


FILENAME = "ismfaenforcedforlocalaccounts.py"


def transformation():
    return load_module(FILENAME)


def test_totp_and_email_with_address_pass_but_email_without_address_fails():
    module = transformation()
    passing = envelope([
        user("totp-user", "totp"),
        user("email-user", "email", email_address="person@example.test"),
    ])
    result = module.transform(passing)["transformedResponse"]
    assert result["isMFAEnforcedForLocalAccounts"] is True
    assert result["scoredLocalAccounts"] == 2
    assert result["compliantLocalAccounts"] == 2

    missing_address = module.transform(envelope([user("email-no-address", "email")]))
    result = missing_address["transformedResponse"]
    assert result["isMFAEnforcedForLocalAccounts"] is False
    assert result["noncompliantLocalAccounts"] == 1
    assert "email-no-address" not in str(missing_address)


def test_direct_and_nested_inherited_otp_and_administrator_exclusion():
    module = transformation()
    users = [
        user("nested", groups=["child"]),
        user("admin", "totp", groups=["admin delegates"]),
    ]
    groups = [
        group("child", members=["nested"]),
        group("parent", "totp", members=["child"]),
        group("SSLVPN Services", members=["child"]),
        group("admin delegates", members=["admin"]),
        group("SonicWall Administrators", "totp", members=["admin delegates"]),
    ]
    result = module.transform(envelope(users, groups))["transformedResponse"]
    assert result["isMFAEnforcedForLocalAccounts"] is True
    assert result["compliantLocalAccounts"] == 1
    assert result["administratorAccountsExcluded"] == 1
    assert result["sslVpnAccounts"] == 1


def test_cycles_ambiguity_and_unknown_evidence_fail_closed():
    module = transformation()
    cycle = envelope(
        [user("cycle-user", "totp", ["cycle-a"])],
        [group("cycle-a", members=["cycle-b", "cycle-user"]), group("cycle-b", members=["cycle-a"])],
    )
    cycle_response = module.transform(cycle)
    assert cycle_response["transformedResponse"]["isMFAEnforcedForLocalAccounts"] is False
    assert cycle_response["transformedResponse"]["unknownAccounts"] == 1

    ambiguous = envelope(
        [user("ambiguous", "totp")],
        [group("ambiguous"), group("parent", "totp", ["ambiguous"])],
    )
    ambiguity_response = module.transform(ambiguous)
    assert ambiguity_response["transformedResponse"]["isMFAEnforcedForLocalAccounts"] is False
    assert "group_membership_unresolved" in ambiguity_response["additionalInfo"]["validation"]["errors"]

    unknown = module.transform(envelope([user("unknown", "unknown")]))
    assert unknown["transformedResponse"]["isMFAEnforcedForLocalAccounts"] is False
    assert unknown["additionalInfo"]["validation"]["status"] == "failed"


def test_empty_population_domain_proxies_and_expired_accounts_are_unscored():
    module = transformation()
    empty = module.transform(envelope())["transformedResponse"]
    assert empty["isMFAEnforcedForLocalAccounts"] is True
    assert empty["scoredLocalAccounts"] == 0

    data = envelope([user("expired", "none", expired=True), user("proxy", "none", domain="example.test")])
    result = module.transform(data)["transformedResponse"]
    assert result["isMFAEnforcedForLocalAccounts"] is True
    assert result["expiredAccounts"] == 1
    assert result["excludedDomainProxies"] == 1
    assert result["scoredLocalAccounts"] == 0


def test_supported_generation_fixtures_are_accepted_but_indeterminate_accounts_do_not_pass():
    module = transformation()
    for contract in ("gen6-combined", "gen6-split", "gen7-split"):
        response = module.transform(fixture_envelope(contract))
        assert response["transformedResponse"]["isMFAEnforcedForLocalAccounts"] is False
        assert response["additionalInfo"]["validation"]["status"] == "failed"
        assert "synthetic-user" not in str(response)


def load_tests(loader, standard_tests, pattern):
    suite = unittest.TestSuite()
    for function_name in sorted(globals()):
        if function_name.startswith("test_"):
            suite.addTest(unittest.FunctionTestCase(globals()[function_name], description=function_name))
    return suite
