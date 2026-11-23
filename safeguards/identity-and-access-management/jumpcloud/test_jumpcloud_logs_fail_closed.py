"""JumpCloud Directory Insights transforms fail closed (2026-09-29, follow-up to #715).

A body that proves nothing (null, an error envelope, unrelated JSON, an empty event list) returns the key
as None with dataCollection.status "error". A read that hit the per-query cap with no match is not scored
as absence. Real bodies still evaluate, and each key counts only its own evidence.
"""
import importlib.util
from pathlib import Path

import pytest

HERE = Path(__file__).parent
KEYS = ["hasAuthenticationLogAPIAccess", "isAuditLoggingEnabled", "isGroupMembershipChangeAudited",
        "isIAMLoggingEnabled", "isMFALoggingEnabled"]
ABSENCE_KEYS = ["hasAuthenticationLogAPIAccess", "isGroupMembershipChangeAudited", "isMFALoggingEnabled"]

NO_EVIDENCE = {
    "null": None,
    "empty_dict": {},
    "empty_list": [],
    "empty_string": "",
    "auth_401": {"message": "Unauthorized", "status": 401},
    "is_error_400": {"error": True, "statusCode": 400, "status": "Error",
                     "message": "start_time is greater than Directory Insights' 90 day retention period"},
    "unrelated": {"items": [{"id": 1}]},
    "not_events": [{"id": 1}, {"id": 2}],
}


def load(key):
    spec = importlib.util.spec_from_file_location("jcl_" + key, HERE / (key + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run(key, body):
    out = load(key).transform(body)
    return out["transformedResponse"][key], out["additionalInfo"]["dataCollection"]["status"]


def ev(event_type, n=0, **kw):
    e = {"id": "e" + str(n), "timestamp": "2026-09-29T00:00:00Z", "event_type": event_type, "service": "directory"}
    e.update(kw)
    return e


def group_change(n=0):
    return ev("association_change", n, association={
        "op": "add", "connection": {"from": {"type": "user_group", "id": "g"}, "to": {"type": "user", "id": "u"}}})


def system_binding(n=0):
    return ev("association_change", n, association={
        "op": "add", "connection": {"from": {"type": "user", "id": "u"}, "to": {"type": "system", "id": "s"}}})


@pytest.mark.parametrize("key", KEYS)
@pytest.mark.parametrize("name", sorted(NO_EVIDENCE))
def test_no_evidence_is_unevaluated(key, name):
    assert run(key, NO_EVIDENCE[name]) == (None, "error")


@pytest.mark.parametrize("key", KEYS)
def test_real_body_passes(key):
    body = [ev("user_login_attempt", 1, mfa=True, mfa_meta={"type": "totp"}), group_change(2), ev("user_update", 3)]
    assert run(key, body) == (True, "success")


@pytest.mark.parametrize("key", KEYS)
def test_wrapped_body_passes(key):
    body = {"apiResponse": [ev("user_login_attempt", 1, mfa=True), group_change(2)]}
    assert run(key, body) == (True, "success")


@pytest.mark.parametrize("key", ABSENCE_KEYS)
def test_complete_read_without_evidence_fails(key):
    body = [ev("user_password_warning_email", 1), system_binding(2), ev("user_login_attempt", 3, mfa=False)
            if key != "hasAuthenticationLogAPIAccess" else ev("user_update", 3)]
    assert run(key, body) == (False, "success")


@pytest.mark.parametrize("key", ABSENCE_KEYS)
def test_capped_read_without_evidence_is_unevaluated(key):
    cap = load(key).PAGE_LIMIT
    body = [ev("user_password_warning_email", i) for i in range(cap)]
    assert run(key, body) == (None, "error")


def test_capped_read_with_evidence_still_passes():
    cap = load("isGroupMembershipChangeAudited").PAGE_LIMIT
    body = [ev("user_password_warning_email", i) for i in range(cap - 1)] + [group_change(cap)]
    assert run("isGroupMembershipChangeAudited", body) == (True, "success")


def test_system_binding_is_not_a_group_membership_change():
    assert run("isGroupMembershipChangeAudited", [system_binding(1)]) == (False, "success")


def test_login_with_mfa_false_is_not_mfa_activity():
    assert run("isMFALoggingEnabled", [ev("user_login_attempt", 1, mfa=False, mfa_meta={})]) == (False, "success")


def test_password_warning_email_is_not_an_authentication_event():
    assert run("hasAuthenticationLogAPIAccess", [ev("user_password_warning_email", 1)]) == (False, "success")
