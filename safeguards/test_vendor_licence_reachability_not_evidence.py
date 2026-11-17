"""A licence check passes on licence evidence, not on a call that answered.

Each vendor rule below used to read an authenticated answer as a purchased licence: a BeyondTrust
vault or managed-account list (even empty), a Liongard environments list or any `count` (`>= 0`
is always true), an Addigy permissions list, an Avanan token or the mere presence of an events
key, and a Qualys portal-version SUCCESS. None of those bodies says anything about a licence, so
each is now Not evaluated (None, with dataCollection.status "error"). An explicit licence field,
a licence error and an expired-subscription code still decide. All bodies are synthetic.
"""
import copy
import importlib.util
import os

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
KEY = "confirmedLicensePurchased"

_MODULES = {}


def load(rel):
    if rel not in _MODULES:
        name = "vendor_lic_" + rel.replace("/", "_").replace("-", "_").replace(".py", "")
        spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, rel))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _MODULES[rel] = module
    return _MODULES[rel]


def run(rel, body, key=KEY):
    out = load(rel).transform(copy.deepcopy(body))
    return out, out.get("transformedResponse", out)[key]


def assert_not_evaluated(out, value):
    assert value is None, out
    collection = out["additionalInfo"]["dataCollection"]
    assert collection["status"] == "error", out
    assert collection["errors"], out


PRA = "iam/beyondtrust-pra/confirmedlicensepurchased.py"
PS = "iam/beyondtrust/confirmedlicensepurchased.py"
PS2 = "identity-and-access-management/beyondtrust/confirmedLicensePurchased.py"
LIONGARD = "epp/liongard/confirmedlicensepurchased.py"
ADDIGY = "epp/addigy/confirmedlicensepurchased.py"
AVANAN = "emailsecurity/avanan/confirmedlicensepurchased.py"
AVANAN_LOG = "emailsecurity/avanan/isemailsecurityloggingenabled.py"
QUALYS = "a6b871e6-de13-41fa-8636-81a3b6f315f4/confirmedlicensepurchased.py"

VAULT_ACCOUNT = {"id": 1, "type": "username_password", "name": "example-account", "account_policy": "default"}
MANAGED_ACCOUNT = {"ManagedAccountID": 1, "SystemName": "example-host", "AccountName": "example-user"}
ENVIRONMENT = {"ID": 1, "Name": "Example environment", "Status": "Active", "Tier": "Core"}
QUALYS_SUCCESS = {"licenseStatus": {"ServiceResponse": {"responseCode": "SUCCESS", "count": "1",
                                                        "data": {"Portal-Version": {"PortalApplication-VERSION": "1.0"}}}}}

REACHABILITY_ONLY = [
    (PRA, [VAULT_ACCOUNT]),
    (PRA, []),
    (PS, [MANAGED_ACCOUNT]),
    (PS, []),
    (PS2, [MANAGED_ACCOUNT]),
    (PS2, []),
    (LIONGARD, {"data": [ENVIRONMENT]}),
    (LIONGARD, {"environments": [ENVIRONMENT]}),
    (LIONGARD, {"count": 0}),
    (LIONGARD, {"count": 3}),
    (LIONGARD, [ENVIRONMENT]),
    (ADDIGY, {"permissions": ["devices:read", "policies:read"]}),
    (ADDIGY, {"data": ["devices:read"]}),
    (AVANAN, {"token": "synthetic-token-value"}),
    (AVANAN, {"securityEvents": []}),
    (AVANAN, {"entities": []}),
    (AVANAN, {"responseData": [{"id": "1"}]}),
    (AVANAN, {"exceptions": []}),
    (QUALYS, QUALYS_SUCCESS),
]


@pytest.mark.parametrize("rel,body", REACHABILITY_ONLY, ids=[f"{r.split('/')[-2]}-{i}" for i, (r, _) in enumerate(REACHABILITY_ONLY)])
def test_an_answer_that_carries_no_licence_is_not_evaluated(rel, body):
    out, value = run(rel, body)
    assert_not_evaluated(out, value)


@pytest.mark.parametrize("rel", [PRA, PS, PS2, LIONGARD, ADDIGY, AVANAN, QUALYS])
def test_an_explicit_licence_field_still_decides(rel):
    assert run(rel, {"licensePurchased": True})[1] is True
    assert run(rel, {"licensePurchased": False})[1] is False


@pytest.mark.parametrize("rel,body", [
    (PRA, {"message": "License expired for this appliance"}),
    (PS, {"Message": "Invalid license"}),
    (PS2, {"Message": "License not found"}),
    (LIONGARD, {"error": "Unauthorized"}),
    (ADDIGY, {"error": "Unauthorized"}),
    (AVANAN, {"error": "Unauthorized"}),
    (QUALYS, {"licenseStatus": {"ServiceResponse": {"responseCode": "SUBSCRIPTION_EXPIRED"}}}),
])
def test_a_licence_error_is_never_a_pass(rel, body):
    out, value = run(rel, body)
    assert value is not True, out


def test_avanan_event_records_still_prove_logging():
    for body in ({"responseData": [{"eventId": "e-1", "eventCreated": "2026-01-01T00:00:00Z", "type": "phishing"}]},
                 {"securityEvents": [{"eventId": "e-1"}]}, {"auditLogs": [{"id": "a-1"}]}):
        assert run(AVANAN_LOG, body, "isEmailSecurityLoggingEnabled")[1] is True, body


def test_avanan_generic_response_rows_are_not_logging_evidence():
    out, value = run(AVANAN_LOG, {"responseData": [{"id": "1", "name": "example"}]}, "isEmailSecurityLoggingEnabled")
    assert_not_evaluated(out, value)
