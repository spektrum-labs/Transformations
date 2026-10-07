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


def test_an_sso_technician_passes():
    assert verdict([tech("SSO"), tech("NATIVE", administrator=True)]) == (True, "success")


def test_only_native_technicians_fail():
    assert verdict([tech("NATIVE"), tech("NATIVE")]) == (False, "success")


def test_an_unrecognised_auth_type_is_not_measured_rather_than_false():
    """The enum spelling comes from the spec, not a captured body. If NinjaOne sends a value
    this check does not know, "no SSO found" is not a measurement."""
    assert verdict([tech("NATIVE"), tech("SAML")]) == (None, "error")


def test_an_unrecognised_auth_type_beside_a_real_sso_still_passes():
    assert verdict([tech("SSO"), tech("SAML")]) == (True, "success")


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
