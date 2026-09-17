import unittest

from conftest import envelope, fixture_envelope, group, load_module, user


FILENAME = "hasidentifiedserviceaccountsmfagap.py"


def transformation():
    return load_module(FILENAME)


def test_only_explicit_prefixes_are_candidates_and_output_is_aggregate_only():
    module = transformation()
    users = [
        user("svc-good", "totp"),
        user("service-gap", "none"),
        user("api-email-no-address", "email"),
        user("bot-email", "email", email_address="bot@example.test"),
        user("automation-admin", "email", ["SonicWall Administrators"], email_address="admin@example.test"),
        user("backup-service", "none"),
    ]
    groups = [group("SonicWall Administrators", members=["automation-admin"])]
    response = module.transform(envelope(users, groups))
    result = response["transformedResponse"]
    assert result["hasIdentifiedServiceAccountsMFAGap"] is True
    assert result["serviceCandidateAccounts"] == 5
    assert result["candidatesWithConfiguredMFA"] == 2
    assert result["candidatesWithoutConfiguredMFA"] == 3
    assert result["administratorCandidates"] == 1
    for account_name in ("svc-good", "service-gap", "api-email-no-address", "bot-email", "automation-admin", "backup-service"):
        assert account_name not in str(response)


def test_empty_candidate_population_and_nested_inherited_totp_have_no_gap():
    module = transformation()
    empty = module.transform(envelope())["transformedResponse"]
    assert empty["hasIdentifiedServiceAccountsMFAGap"] is False
    assert empty["serviceCandidateAccounts"] == 0

    groups = [group("child", members=["svc-nested"]), group("parent", "totp", ["child"])]
    nested = module.transform(envelope([user("svc-nested", "none", ["child"])], groups))["transformedResponse"]
    assert nested["hasIdentifiedServiceAccountsMFAGap"] is False
    assert nested["candidatesWithConfiguredMFA"] == 1


def test_cycle_ambiguity_and_unknown_input_report_a_gap_fail_closed():
    module = transformation()
    cycle = envelope(
        [user("svc-cycle", "totp", ["cycle-a"])],
        [group("cycle-a", members=["cycle-b", "svc-cycle"]), group("cycle-b", members=["cycle-a"])],
    )
    cycle_response = module.transform(cycle)
    assert cycle_response["transformedResponse"]["hasIdentifiedServiceAccountsMFAGap"] is True
    assert cycle_response["transformedResponse"]["unknownAccounts"] == 1

    ambiguous = envelope(
        [user("svc-same", "totp")],
        [group("svc-same"), group("parent", "totp", ["svc-same"])],
    )
    ambiguity_response = module.transform(ambiguous)
    assert ambiguity_response["transformedResponse"]["hasIdentifiedServiceAccountsMFAGap"] is True
    assert "group_membership_unresolved" in ambiguity_response["additionalInfo"]["validation"]["errors"]

    unknown_state = module.transform(envelope([user("api-unknown", "totp", include_state=False)]))
    assert unknown_state["transformedResponse"]["hasIdentifiedServiceAccountsMFAGap"] is True
    assert unknown_state["additionalInfo"]["validation"]["status"] == "failed"

    malformed = envelope()
    malformed["counts"]["rawUserEntries"] = 1
    assert module.transform(malformed)["transformedResponse"]["hasIdentifiedServiceAccountsMFAGap"] is True


def test_expired_and_domain_candidates_are_reported_but_unscored():
    module = transformation()
    response = module.transform(envelope([
        user("svc-expired", "none", expired=True),
        user("api-domain", "none", domain="example.test"),
    ]))
    result = response["transformedResponse"]
    assert result["hasIdentifiedServiceAccountsMFAGap"] is False
    assert result["serviceCandidateAccounts"] == 2
    assert result["expiredCandidates"] == 1
    assert result["excludedDomainProxies"] == 1
    assert result["candidatesWithoutConfiguredMFA"] == 0


def test_supported_generation_fixtures_are_compatible_and_nonprefix_names_are_not_candidates():
    module = transformation()
    for contract in ("gen6-combined", "gen6-split", "gen7-split"):
        response = module.transform(fixture_envelope(contract))
        result = response["transformedResponse"]
        assert result["hasIdentifiedServiceAccountsMFAGap"] is False
        assert result["serviceCandidateAccounts"] == 0
        assert response["additionalInfo"]["validation"]["status"] == "passed"
        assert "synthetic-" not in str(response)


def load_tests(loader, standard_tests, pattern):
    suite = unittest.TestSuite()
    for function_name in sorted(globals()):
        if function_name.startswith("test_"):
            suite.addTest(unittest.FunctionTestCase(globals()[function_name], description=function_name))
    return suite
