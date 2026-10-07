"""NinjaOne isSSOEnabled reads technician authType, and nothing else answers it.

The file used to answer `data.get('isSSOEnabled', affirmative_signal(data))`. NinjaOne sends no
such field, so any non-empty body -- a device list included -- read as SSO enabled. Bodies are
synthetic, shaped from the NinjaOne Public API 2.0 Technician schema (GET /v2/user/technicians).
"""
import importlib.util
import os

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))


def load():
    spec = importlib.util.spec_from_file_location("ninjaone_isidpenabled", os.path.join(HERE, "isidpenabled.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def tech(auth="SSO", enabled=True, invitation="REGISTERED", **extra):
    record = {"id": 1, "uid": "00000000-0000-0000-0000-000000000001", "enabled": enabled,
              "firstName": "Test", "lastName": "Technician", "email": "tech@example.com",
              "mustChangePw": False, "mfaConfigured": True, "scimUser": False, "authType": auth,
              "userType": "TECHNICIAN", "invitationStatus": invitation, "administrator": False}
    record.update(extra)
    return record


class Poisoned(dict):
    """A non-empty object whose every read raises, to drive the transform's except path."""

    def __init__(self):
        super().__init__(poisoned=True)

    def boom(self, *args, **kwargs):
        raise RuntimeError("poisoned read")

    get = __getitem__ = __contains__ = keys = items = values = __iter__ = boom

    def __len__(self):
        return 1


def verdict(body):
    out = load().transform(body)
    return out["transformedResponse"]["isSSOEnabled"], out["additionalInfo"]["dataCollection"]["status"]


def test_every_technician_on_sso_passes():
    assert verdict([tech("SSO"), tech("SSO", administrator=True)]) == (True, "success")


def test_one_native_technician_fails_even_beside_sso_ones():
    """Technicians administer the tool, so one native sign-in is an administrator outside
    the identity provider."""
    assert verdict([tech("SSO"), tech("NATIVE", administrator=True)]) == (False, "success")


def test_only_native_technicians_fail():
    assert verdict([tech("NATIVE"), tech("NATIVE")]) == (False, "success")


def test_an_unrecognised_auth_type_beside_sso_is_not_measured():
    """The enum spelling comes from the spec, not a captured body. With no native technician,
    "all on SSO" cannot be confirmed while any authType is unrecognised."""
    assert verdict([tech("SSO"), tech("SAML")]) == (None, "error")


def test_a_native_technician_fails_even_beside_an_unrecognised_auth_type():
    # A known native sign-in already fails "every technician on SSO", whatever the rest are.
    assert verdict([tech("NATIVE"), tech("SAML")]) == (False, "success")


def test_an_active_technician_without_a_usable_auth_type_is_not_measured():
    missing = tech("NATIVE")
    del missing["authType"]
    assert verdict([tech("SSO"), tech("NATIVE", authType=None)]) == (None, "error")
    assert verdict([tech("SSO"), missing]) == (None, "error")
    assert verdict([tech("SSO"), tech("NATIVE", authType=5)]) == (None, "error")
    # an inactive record without authType does not block the pass
    assert verdict([tech("SSO"), tech("NATIVE", enabled=False, authType=None)]) == (True, "success")


def test_a_data_wrapped_technician_list_is_read():
    assert verdict({"data": [tech("SSO")]}) == (True, "success")


def test_disabled_and_unregistered_sso_technicians_do_not_count():
    body = [tech("NATIVE"), tech("SSO", enabled=False), tech("SSO", invitation="PENDING")]
    assert verdict(body) == (False, "success")


def test_auth_type_is_compared_case_insensitively():
    assert verdict({"response": [tech("sso")]}) == (True, "success")


@pytest.mark.parametrize("body", [
    {},
    [],
    None,
    "not json",
    {"resultCode": "FAILURE", "errorMessage": "Unauthorized", "incidentId": "x"},
    {"statusCode": 403},
    # the old false PASS: a device list is a non-empty collection, and says nothing about sign-in
    [{"id": 7, "systemName": "WS-01", "nodeClass": "WINDOWS_WORKSTATION", "offline": False}],
    {"isSSOEnabled": True},
    [tech("SSO", enabled=False)],
], ids=["empty", "empty-list", "none", "string", "ninja-error", "http-403", "device-list",
        "self-answer", "no-active-technician"])
def test_no_evidence_is_not_evaluated(body):
    assert verdict(body) == (None, "error")


def test_poisoned_body_is_not_evaluated():
    assert verdict(Poisoned()) == (None, "error")
