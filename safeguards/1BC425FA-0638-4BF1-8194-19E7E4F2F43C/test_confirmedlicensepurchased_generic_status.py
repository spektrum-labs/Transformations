"""A generic status, HTTP code or unknown shape is not a Sophos licence.

This transform is also wired to non-Sophos integrations, whose licence reads answer with
bodies such as {"message": ..., "status": "ok"}, {"status": 200} or a list of records. The
old fallback read any `status` value of "ok"/"success" or a positive number, and any
populated list, as an active licence, so those bodies passed confirmedLicensePurchased.
Only licensePurchased true/false or the Sophos product flags may decide it; everything
else is Not evaluated (None, with a data-collection error so the evaluator records it as
not evaluated). Synthetic bodies only.
"""
import importlib.util
import json
import pathlib

import pytest

HERE = pathlib.Path(__file__).parent
KEY = "confirmedLicensePurchased"


def run(body):
    spec = importlib.util.spec_from_file_location("sophos_license_generic", HERE / "confirmedlicensepurchased.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform(body)


NOT_LICENCE_EVIDENCE = [
    {"status": "ok"},
    {"status": 200},
    {"status": "200"},
    {"message": "x", "status": "success"},
    {"message": "OK", "status": "active"},
    {"enabled": True},
    {"active": True, "state": "valid"},
    {"response": {"status": "ok"}},
    {"apiResponse": {"status": "success"}},
    {"items": [{"id": "00000000-0000-0000-0000-000000000001"}]},
    {"licenses": [{"id": "lic-1", "status": "expired"}]},
    {"data": {"plan": "example"}},
    [{"id": "00000000-0000-0000-0000-000000000001"}],
    "<html><body>Sign in</body></html>",
    "<!DOCTYPE html><html><head><title>200 OK</title></head></html>",
    "OK",
    "true",
    {},
    [],
    None,
]


@pytest.mark.parametrize("body", NOT_LICENCE_EVIDENCE, ids=lambda b: json.dumps(b)[:48])
def test_body_without_sophos_licence_evidence_is_not_evaluated(body):
    out = run(body)
    assert out["transformedResponse"][KEY] is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"
    assert out["additionalInfo"]["evaluation"]["passReasons"] == []


@pytest.mark.parametrize("body", [{"status": 401, "licensePurchased": True},
                                  {"statusCode": "503", "isEPPConfigured": "false"},
                                  {"error": "Forbidden", "licensePurchased": True},
                                  {"errorCode": "E0000011", "isEPPConfigured": False}],
                         ids=lambda b: json.dumps(b)[:48])
def test_error_body_is_not_evaluated_even_beside_licence_keys(body):
    out = run(body)
    assert out["transformedResponse"][KEY] is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"


@pytest.mark.parametrize("value", ["false", "yes", 1, 0, "", None, {"value": True}])
def test_license_purchased_must_be_a_real_boolean_to_pass(value):
    out = run({"licensePurchased": value})
    result = out["transformedResponse"][KEY]
    assert result is not True
    if value == "false":
        assert result is False
    else:
        assert result is None
        assert out["additionalInfo"]["dataCollection"]["status"] == "error"


@pytest.mark.parametrize("body, expected", [
    ({"licensePurchased": True}, True),
    ({"licensePurchased": "true"}, True),
    ({"licensePurchased": False}, False),
    ({"response": {"licensePurchased": True}}, True),
    ({"licensePurchased": True, "status": "ok"}, True),
    ({"isEPPConfigured": "false", "isMDRConfigured": "false"}, False),
    ({"isEPPConfigured": False, "status": "ok"}, False),
    ({"isEPPConfigured": "true", "isMDRConfigured": "true"}, None),
    ({"isFirewallConfigured": True, "status": "ok"}, None),
], ids=lambda b: json.dumps(b)[:48])
def test_sophos_licence_bodies_keep_their_reading(body, expected):
    assert run(body)["transformedResponse"][KEY] is expected


def test_validation_failure_is_not_evaluated():
    out = run({"data": {"licensePurchased": True}, "validation": {"status": "failed", "errors": ["x"]}})
    assert out["transformedResponse"][KEY] is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"
