import ast
import unittest

from conftest import ROOT, envelope, fixture_envelope, load_module, user


FILENAME = "haslocalaccountinventoryvisibility.py"


def transformation():
    return load_module(FILENAME)


def test_valid_empty_inventory_and_domain_expired_classification():
    module = transformation()
    empty = module.transform(envelope())
    assert empty["transformedResponse"] == {
        "hasLocalAccountInventoryVisibility": True,
        "totalLocalAccounts": 0,
        "activeLocalAccounts": 0,
        "expiredAccounts": 0,
        "excludedDomainProxies": 0,
        "unknownAccounts": 0,
    }
    data = envelope([
        user("active", "totp"),
        user("expired", expired=True),
        user("proxy", domain="example.test"),
    ])
    result = module.transform(data)["transformedResponse"]
    assert result["hasLocalAccountInventoryVisibility"] is True
    assert result["totalLocalAccounts"] == 2
    assert result["activeLocalAccounts"] == 1
    assert result["expiredAccounts"] == 1
    assert result["excludedDomainProxies"] == 1


def test_unknown_partial_and_duplicate_evidence_fail_closed():
    module = transformation()
    unknown = module.transform(envelope([user("unknown-state", include_state=False)]))
    assert unknown["transformedResponse"]["hasLocalAccountInventoryVisibility"] is False
    assert unknown["transformedResponse"]["unknownAccounts"] == 1
    assert unknown["additionalInfo"]["validation"]["status"] == "failed"

    partial = envelope()
    del partial["evidence"]["localUsers"]
    assert module.transform(partial)["transformedResponse"]["hasLocalAccountInventoryVisibility"] is False

    duplicates = envelope([user("same", vendor_uuid="same-id"), user("other", vendor_uuid="same-id")])
    duplicate_response = module.transform(duplicates)
    assert duplicate_response["transformedResponse"]["hasLocalAccountInventoryVisibility"] is False
    assert "duplicate_local_user_identity" in duplicate_response["additionalInfo"]["validation"]["errors"]


def test_gen6_and_gen7_fixtures_are_normalized_and_fail_closed_when_indeterminate():
    module = transformation()
    for contract in ("gen6-combined", "gen6-split", "gen7-split"):
        result = module.transform(fixture_envelope(contract))
        assert result["transformedResponse"]["hasLocalAccountInventoryVisibility"] is False
        assert result["transformedResponse"]["unknownAccounts"] > 0
        assert "synthetic-user" not in str(result)


def test_all_five_schemas_accept_collector_contract_and_scripts_follow_restricted_conventions():
    filenames = (
        "haslocalaccountinventoryvisibility.py",
        "ismfaenforcedforlocalaccounts.py",
        "ismfaenforcedforadministratoraccounts.py",
        "isbuiltinadministratormfabound.py",
        "hasidentifiedserviceaccountsmfagap.py",
    )
    data = envelope()
    for filename in filenames:
        schema = load_module(filename, ROOT / "schemas")
        model_name = filename[:-3].capitalize() + "Input"
        model = getattr(schema, model_name)
        model(**data)
        missing_evidence = dict(data)
        del missing_evidence["evidence"]
        rejected = False
        try:
            model(**missing_evidence)
        except Exception:
            rejected = True
        assert rejected

        source = (ROOT / filename).read_text()
        tree = ast.parse(source)
        compile(source, filename, "exec")
        for node in ast.walk(tree):
            assert not (isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Subscript))
            if isinstance(node, ast.Import):
                assert all(alias.name in ("json",) for alias in node.names)
            if isinstance(node, ast.ImportFrom):
                assert node.module == "datetime"


def test_partial_collector_envelope_cannot_look_safe_for_any_criterion():
    expected = {
        "haslocalaccountinventoryvisibility.py": ("hasLocalAccountInventoryVisibility", False),
        "ismfaenforcedforlocalaccounts.py": ("isMFAEnforcedForLocalAccounts", False),
        "ismfaenforcedforadministratoraccounts.py": ("isMFAEnforcedForAdministratorAccounts", False),
        "isbuiltinadministratormfabound.py": ("isBuiltInAdministratorMFABound", False),
        "hasidentifiedserviceaccountsmfagap.py": ("hasIdentifiedServiceAccountsMFAGap", True),
    }
    data = envelope()
    del data["evidence"]["administrationGlobal"]
    for filename in expected:
        key, safe_value = expected[filename]
        response = load_module(filename).transform(data)
        assert response["transformedResponse"][key] is safe_value
        assert response["additionalInfo"]["validation"]["status"] == "failed"


def test_partial_upstream_validation_and_mixed_profile_shapes_fail_closed():
    expected = {
        "haslocalaccountinventoryvisibility.py": ("hasLocalAccountInventoryVisibility", False),
        "ismfaenforcedforlocalaccounts.py": ("isMFAEnforcedForLocalAccounts", False),
        "ismfaenforcedforadministratoraccounts.py": ("isMFAEnforcedForAdministratorAccounts", False),
        "isbuiltinadministratormfabound.py": ("isBuiltInAdministratorMFABound", False),
        "hasidentifiedserviceaccountsmfagap.py": ("hasIdentifiedServiceAccountsMFAGap", True),
    }
    for filename in expected:
        key, safe_value = expected[filename]
        module = load_module(filename)
        wrapper = {"data": envelope(), "validation": {"status": "passed"}}
        wrapper_response = module.transform(wrapper)
        assert wrapper_response["transformedResponse"][key] is safe_value
        assert wrapper_response["additionalInfo"]["validation"]["status"] == "failed"

        mixed_form = envelope()
        mixed_form["data"] = envelope()
        mixed_form["validation"] = {"status": "passed", "errors": [], "warnings": []}
        mixed_form_response = module.transform(mixed_form)
        assert mixed_form_response["transformedResponse"][key] is safe_value
        assert mixed_form_response["additionalInfo"]["validation"]["status"] == "failed"

        legacy_mixed = envelope()
        legacy_mixed["counts"]["rawUserEntries"] = 99
        legacy_mixed["response"] = envelope()
        legacy_mixed_response = module.transform(legacy_mixed)
        assert legacy_mixed_response["transformedResponse"][key] is safe_value
        assert "raw_user_count_mismatch" in legacy_mixed_response["additionalInfo"]["validation"]["errors"]

        mixed_profile = envelope()
        mixed_profile["evidence"]["localUsers"]["user"]["local"]["group"] = []
        mixed_response = module.transform(mixed_profile)
        assert mixed_response["transformedResponse"][key] is safe_value
        assert "split_contract_has_combined_groups" in mixed_response["additionalInfo"]["validation"]["errors"]


def load_tests(loader, standard_tests, pattern):
    suite = unittest.TestSuite()
    for function_name in sorted(globals()):
        if function_name.startswith("test_"):
            suite.addTest(unittest.FunctionTestCase(globals()[function_name], description=function_name))
    return suite
