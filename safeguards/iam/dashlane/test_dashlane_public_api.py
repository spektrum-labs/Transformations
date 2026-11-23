"""Dashlane transforms read the Public API shapes (POST /public/teams/Members and /public/teams/Status) and say None when nothing proves an answer."""
import importlib.util
import os

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name):
    spec = importlib.util.spec_from_file_location("dashlane_" + name, os.path.join(HERE, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def member(i, auth="totp_login", status="accepted", admin=False, billing=False):
    authentication = {"type": auth, "lastUpdateDate": 1760000000} if auth is not None else None
    return {
        "email": "user" + str(i) + "@example.test",
        "status": status,
        "joinedDate": 1750000000,
        "role": {"billingAdmin": billing, "teamAdmin": admin, "groupManager": False},
        "authentication": authentication,
        "passwordsTotal": 12,
    }


def members_body(items, truncated=False):
    inner = {"requestId": "req-0001", "data": {"members": items}}
    if truncated:
        inner["paginationTruncated"] = True
    return {"data": {"apiResponse": inner}, "validation": {"status": "skipped", "errors": [], "warnings": []}}


def status_body(active=5, pending=1, remaining=4):
    inner = {"requestId": "req-0002", "data": {"seats": {"active": active, "pending": pending, "extraFree": 0, "remaining": remaining},
                                               "creationDate": 1700000000, "name": "Example Team", "sso": {"enabled": False, "domains": []}}}
    return {"data": {"apiResponse": inner}, "validation": {"status": "skipped", "errors": [], "warnings": []}}


def out(name, payload):
    return load(name)(payload)


def value(name, key, payload):
    return out(name, payload)["transformedResponse"][key]


def not_evaluated(result, key):
    return result["transformedResponse"][key] is None and result["additionalInfo"]["dataCollection"]["status"] == "error"


# ---- isStrongAuthRequired -------------------------------------------------

def test_every_active_member_on_strong_auth_passes():
    items = [member(1, "sso"), member(2, "totp_login"), member(3, "totp_device_registration")]
    result = out("isstrongauthrequired", members_body(items))
    assert result["transformedResponse"]["isStrongAuthRequired"] is True
    assert result["transformedResponse"]["strongAuthMembers"] == 3
    assert result["additionalInfo"]["dataCollection"]["status"] == "success"


def test_one_member_on_an_emailed_code_fails():
    items = [member(1, "sso"), member(2, "email_token")]
    result = out("isstrongauthrequired", members_body(items))
    assert result["transformedResponse"]["isStrongAuthRequired"] is False
    assert result["transformedResponse"]["membersWithoutStrongAuth"] == 1


def test_a_member_with_no_authentication_fails():
    assert value("isstrongauthrequired", "isStrongAuthRequired", members_body([member(1, "sso"), member(2, None)])) is False


def test_flipping_one_member_flips_the_answer():
    assert value("isstrongauthrequired", "isStrongAuthRequired", members_body([member(1, "totp_login"), member(2, "totp_login")])) is True
    assert value("isstrongauthrequired", "isStrongAuthRequired", members_body([member(1, "totp_login"), member(2, "email_token")])) is False


def test_only_active_members_are_judged():
    items = [member(1, "sso"), member(2, "email_token", status="removed"), member(3, "email_token", status="proposed")]
    assert value("isstrongauthrequired", "isStrongAuthRequired", members_body(items)) is True


def test_no_active_member_is_not_measured():
    assert not_evaluated(out("isstrongauthrequired", members_body([member(1, "sso", status="proposed")])), "isStrongAuthRequired")
    assert not_evaluated(out("isstrongauthrequired", members_body([])), "isStrongAuthRequired")


def test_unknown_authentication_type_is_not_strong():
    assert value("isstrongauthrequired", "isStrongAuthRequired", members_body([member(1, "something_new")])) is False


def test_partial_read_is_not_scored():
    assert not_evaluated(out("isstrongauthrequired", members_body([member(1, "sso")], truncated=True)), "isStrongAuthRequired")


# ---- isMFAEnforcedForAdmins ----------------------------------------------

def test_admins_on_strong_auth_pass_even_when_users_are_not():
    items = [member(1, "totp_login", admin=True), member(2, "email_token"), member(3, "sso", billing=True)]
    result = out("ismfaenforcedforadmins", members_body(items))
    assert result["transformedResponse"]["isMFAEnforcedForAdmins"] is True
    assert result["transformedResponse"]["activeAdmins"] == 2


def test_an_admin_on_an_emailed_code_fails():
    items = [member(1, "totp_login", admin=True), member(2, "email_token", admin=True)]
    assert value("ismfaenforcedforadmins", "isMFAEnforcedForAdmins", members_body(items)) is False


def test_a_billing_admin_counts_as_an_admin():
    assert value("ismfaenforcedforadmins", "isMFAEnforcedForAdmins", members_body([member(1, "email_token", billing=True)])) is False


def test_no_admin_in_the_list_is_not_measured():
    assert not_evaluated(out("ismfaenforcedforadmins", members_body([member(1, "sso"), member(2, "sso")])), "isMFAEnforcedForAdmins")


def test_a_removed_admin_is_not_judged():
    items = [member(1, "sso", admin=True), member(2, "email_token", admin=True, status="removed")]
    assert value("ismfaenforcedforadmins", "isMFAEnforcedForAdmins", members_body(items)) is True


def test_admin_partial_read_is_not_scored():
    assert not_evaluated(out("ismfaenforcedforadmins", members_body([member(1, "sso", admin=True)], truncated=True)), "isMFAEnforcedForAdmins")


# ---- confirmedLicensePurchased --------------------------------------------

def test_an_active_seat_is_a_licence():
    result = out("confirmedlicensepurchased", status_body(active=3))
    assert result["transformedResponse"]["confirmedLicensePurchased"] is True
    assert result["transformedResponse"]["activeSeats"] == 3


def test_no_active_seat_is_not_a_licence():
    assert value("confirmedlicensepurchased", "confirmedLicensePurchased", status_body(active=0, pending=2)) is False


def test_a_status_without_a_seat_count_is_not_measured():
    payload = {"data": {"apiResponse": {"requestId": "r", "data": {"seats": {"pending": 1}, "name": "x"}}}, "validation": {}}
    assert not_evaluated(out("confirmedlicensepurchased", payload), "confirmedLicensePurchased")
    payload = {"data": {"apiResponse": {"requestId": "r", "data": {"seats": {"active": "5"}}}}, "validation": {}}
    assert not_evaluated(out("confirmedlicensepurchased", payload), "confirmedLicensePurchased")
    payload = {"data": {"apiResponse": {"requestId": "r", "data": {"seats": {"active": True}}}}, "validation": {}}
    assert not_evaluated(out("confirmedlicensepurchased", payload), "confirmedLicensePurchased")


# ---- no evidence ------------------------------------------------------------

NO_EVIDENCE = [
    None, {}, [], "", "{}",
    {"errors": ["Unauthorized"]},
    {"error": "invalid credentials", "status_code": 401},
    {"statusCode": 403, "error": "Forbidden"},
    {"data": {"apiResponse": {"errors": {"code": "unauthorized", "type": "business_error"}}}, "validation": {}},
    {"data": {"apiResponse": {"status_code": 500, "message": "boom"}}, "validation": {}},
    {"data": {"unrelated": 1}, "validation": {"status": "skipped", "errors": [], "warnings": []}},
]
KEYS = [("isstrongauthrequired", "isStrongAuthRequired"), ("ismfaenforcedforadmins", "isMFAEnforcedForAdmins"),
        ("confirmedlicensepurchased", "confirmedLicensePurchased")]


@pytest.mark.parametrize("name,key", KEYS)
@pytest.mark.parametrize("payload", NO_EVIDENCE)
def test_no_evidence_is_not_measured(name, key, payload):
    assert not_evaluated(out(name, payload), key)


@pytest.mark.parametrize("name,key", KEYS[:2])
@pytest.mark.parametrize("junk", [["a", "b"], [1, 2], [None], "members"])
def test_members_that_are_not_records_are_not_scored(name, key, junk):
    assert not_evaluated(out(name, members_body(junk)), key)
