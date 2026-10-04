"""Shared Sophos confirmedLicensePurchased reads the healthCheck product flags.

The Sophos Email Security and Firewall integrations bind this file to the healthCheck read,
which returns {"isEPPConfigured": "true", "isMDRConfigured": "true"} (strings or booleans).
Before this fix none of those keys was recognised and every such body read False with an
MDR-only reason. Synthetic bodies only.
"""
import importlib.util
import json
import pathlib

import pytest

HERE = pathlib.Path(__file__).parent
KEY = "confirmedLicensePurchased"


def run(body):
    spec = importlib.util.spec_from_file_location("sophos_license", HERE / "confirmedlicensepurchased.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform(body)


@pytest.mark.parametrize("body", [{"isEPPConfigured": "true", "isMDRConfigured": "true"},
                                  {"isEPPConfigured": True, "isMDRConfigured": False},
                                  {"isEPPConfigured": "false", "isMDRConfigured": "TRUE"},
                                  {"isFirewallConfigured": "true"},
                                  {"isEmailConfigured": True}],
                         ids=lambda b: json.dumps(b)[:40])
def test_a_true_product_flag_is_true(body):
    out = run(body)
    assert out["transformedResponse"][KEY] is True
    assert out["additionalInfo"]["evaluation"]["passReasons"][0].startswith("Sophos licence confirmed")


def test_reason_names_the_products_returned_not_only_mdr():
    reason = run({"isEPPConfigured": "true", "isMDRConfigured": "false"})["additionalInfo"]["evaluation"]["passReasons"][0]
    assert "Endpoint Protection" in reason and "MDR" not in reason


@pytest.mark.parametrize("body", [{"isEPPConfigured": "false", "isMDRConfigured": "false"},
                                  {"isEPPConfigured": False}],
                         ids=lambda b: json.dumps(b)[:40])
def test_all_flags_explicitly_false_is_false(body):
    out = run(body)
    assert out["transformedResponse"][KEY] is False
    assert "MDR license" not in out["additionalInfo"]["evaluation"]["failReasons"][0]


@pytest.mark.parametrize("body", [{}, None, "{}", [], {"error": "Unauthorized"},
                                  {"message": "Integration execution error: HTTP 401"},
                                  {"isEPPConfigured": "unknown"}],
                         ids=lambda b: json.dumps(b)[:40])
def test_no_readable_flag_is_not_evaluated(body):
    out = run(body)
    assert out["transformedResponse"][KEY] is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"


def test_string_body_is_parsed():
    assert run(json.dumps({"isEPPConfigured": "true"}))["transformedResponse"][KEY] is True


def test_legacy_license_purchased_key_still_honoured():
    assert run({"licensePurchased": True})["transformedResponse"][KEY] is True
    assert run({"licensePurchased": False})["transformedResponse"][KEY] is False
