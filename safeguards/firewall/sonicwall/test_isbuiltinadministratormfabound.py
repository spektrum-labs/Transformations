import unittest

from conftest import envelope, fixture_envelope, load_module


FILENAME = "isbuiltinadministratormfabound.py"


def transformation():
    return load_module(FILENAME)


def test_exact_builtin_totp_setting_passes_and_is_described_as_configuration_only():
    response = transformation().transform(envelope())
    result = response["transformedResponse"]
    assert result == {
        "isBuiltInAdministratorMFABound": True,
        "builtInAdministratorAccounts": 1,
        "totpConfiguredAccounts": 1,
        "notTotpConfiguredAccounts": 0,
        "unknownAccounts": 0,
    }
    evaluation = response["additionalInfo"]["evaluation"]
    prose = str(evaluation).lower()
    assert "totp is configured" in prose
    assert "does not prove" in prose
    assert "bound to a person" in prose
    assert "enforced during authentication" in prose


def test_explicit_false_is_confirmed_not_configured():
    admin = {"name": "built-in-administrator", "one_time_password": {"totp": False}}
    response = transformation().transform(envelope(admin=admin))
    result = response["transformedResponse"]
    assert result["isBuiltInAdministratorMFABound"] is False
    assert result["notTotpConfiguredAccounts"] == 1
    assert result["unknownAccounts"] == 0
    assert response["additionalInfo"]["validation"]["status"] == "passed"


def test_missing_ambiguous_and_partial_builtin_evidence_fail_closed():
    module = transformation()
    missing = {"name": "built-in-administrator"}
    missing_response = module.transform(envelope(admin=missing))
    assert missing_response["transformedResponse"]["isBuiltInAdministratorMFABound"] is False
    assert missing_response["transformedResponse"]["unknownAccounts"] == 1
    assert missing_response["additionalInfo"]["validation"]["status"] == "failed"

    ambiguous = {"name": "built-in-administrator", "one_time_password": {"totp": True, "otp": True}}
    assert module.transform(envelope(admin=ambiguous))["transformedResponse"]["isBuiltInAdministratorMFABound"] is False

    partial = envelope()
    del partial["evidence"]["administrationGlobal"]
    assert module.transform(partial)["transformedResponse"]["isBuiltInAdministratorMFABound"] is False

    simplified = envelope()
    simplified["evidence"]["administrationGlobal"] = {
        "administration": {
            "admin": {
                "name": "built-in-administrator",
                "one_time_password": {"totp": True},
            }
        }
    }
    simplified_response = module.transform(simplified)
    assert simplified_response["transformedResponse"]["isBuiltInAdministratorMFABound"] is False
    assert "built_in_administrator_shape_unrecognized" in simplified_response["additionalInfo"]["validation"]["errors"]


def test_gen6_and_gen7_administration_fixtures_show_totp_configured():
    module = transformation()
    for contract in ("gen6-combined", "gen6-split", "gen7-split"):
        response = module.transform(fixture_envelope(contract))
        assert response["transformedResponse"]["isBuiltInAdministratorMFABound"] is True
        assert response["transformedResponse"]["totpConfiguredAccounts"] == 1
        assert "synthetic-built-in-admin" not in str(response)


def load_tests(loader, standard_tests, pattern):
    suite = unittest.TestSuite()
    for function_name in sorted(globals()):
        if function_name.startswith("test_"):
            suite.addTest(unittest.FunctionTestCase(globals()[function_name], description=function_name))
    return suite
