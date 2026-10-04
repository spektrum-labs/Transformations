"""Shared Sophos confirmedLicensePurchased reads the healthCheck product flags.

The Sophos Email Security and Firewall integrations bind this file to the healthCheck read,
which returns {"isEPPConfigured": "true", "isMDRConfigured": "true"} (strings or booleans).
Before this fix none of those keys was recognised and every such body read False with an
MDR-only reason. The read does not say which product row asked, so a true flag is Not
evaluated (it cannot prove a Firewall licence from an EPP flag); only all-false is False.
Synthetic bodies only.
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
def test_a_true_flag_is_not_evaluated_because_the_product_is_unknown(body):
    out = run(body)
    assert out["transformedResponse"][KEY] is None
    assert out["additionalInfo"]["evaluation"]["failReasons"][0] == (
        "Sophos healthCheck does not say which product is licensed; "
        "a per-product licence read (getLicenses) is needed")
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"


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
    assert run(json.dumps({"isEPPConfigured": "false"}))["transformedResponse"][KEY] is False


def test_legacy_license_purchased_key_still_honoured():
    assert run({"licensePurchased": True})["transformedResponse"][KEY] is True
    assert run({"licensePurchased": False})["transformedResponse"][KEY] is False
