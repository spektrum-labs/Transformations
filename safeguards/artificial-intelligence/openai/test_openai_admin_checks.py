"""OpenAI Administration API checks, on the documented response schemas (openai-openapi master).
No live admin payload yet: each check has a passing body, a flip that must fail, and the
fail-closed bodies. Prod hands these files the enriched {"data": body, "validation": ...} input
because they read input.get("data"), so both forms are exercised."""
import copy
import importlib.util
import json
import pathlib
import time

import pytest

HERE = pathlib.Path(__file__).resolve().parent
NOW = int(time.time())
DAY = 86400


def load(name):
    spec = importlib.util.spec_from_file_location("openai_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def lst(items, has_more=False):
    return {"object": "list", "data": list(items), "has_more": has_more}


def user(uid, role="reader", scim=True, sa=False):
    return {"object": "organization.user", "id": uid, "role": role, "added_at": NOW,
            "is_service_account": sa, "is_scim_managed": scim}


def admin_key(kid, expires=True, used=1):
    return {"object": "organization.admin_api_key", "id": kid, "name": kid, "created_at": NOW - 30 * DAY,
            "expires_at": NOW + 300 * DAY if expires else None, "last_used_at": NOW - used * DAY, "owner": {"type": "user"}}


def project(pid):
    return {"id": pid, "object": "organization.project", "name": pid, "created_at": NOW - 300 * DAY,
            "archived_at": None, "status": "active"}


def proj_key(kid, owner="service_account", used=1):
    return {"object": "organization.project.api_key", "id": kid, "name": kid, "created_at": NOW - 30 * DAY,
            "last_used_at": NOW - used * DAY, "owner_project_access": "active", "owner": {"type": owner}}


def flip(base, fn):
    p = copy.deepcopy(base)
    fn(p)
    return p


USERS = lst([user("u1", "owner"), user("u2", "owner", scim=False)] + [user("r%d" % i) for i in range(6)])
ADMIN = lst([admin_key("a1"), admin_key("a2")])
CRED = dict(lst([project("p1"), project("p2")]), adminApiKeys=ADMIN,
            projectApiKeys=[lst([proj_key("k1")]), lst([proj_key("k2")])])
RET = dict(lst([project("p1")]), orgDataRetention={"object": "organization.data_retention", "type": "zero_data_retention"},
           projectDataRetention=[{"object": "project.data_retention", "type": "organization_default"}])
SPEND = {"object": "organization.spend_limit", "threshold_amount": 100000, "currency": "USD", "interval": "month",
         "enforcement": {"status": "enforcing"}}

CASES = [
    ("isactivityaudittrailenabled", "isActivityAuditTrailEnabled",
     lst([{"id": "audit_log-1", "type": "login.succeeded", "effective_at": NOW - DAY}]), lst([{"note": "not an event"}])),
    ("isprivilegedaccesslimited", "isPrivilegedAccessLimited", USERS,
     flip(USERS, lambda p: p["data"][2].update(role="owner"))),
    ("isscimprovisioningenabled", "isSCIMProvisioningEnabled", USERS,
     lst([user("u1", "owner", scim=False), user("s1", scim=True, sa=True)])),
    ("iscredentialexpirationenforced", "isCredentialExpirationEnforced", ADMIN,
     flip(ADMIN, lambda p: p["data"][0].update(expires_at=None))),
    ("isstalecredentialsremoved", "isStaleCredentialsRemoved", CRED,
     flip(CRED, lambda p: p["projectApiKeys"][1]["data"][0].update(last_used_at=NOW - 120 * DAY))),
    ("isenvironmentisolationenforced", "isEnvironmentIsolationEnforced", CRED,
     flip(CRED, lambda p: p["projectApiKeys"][0]["data"][0].update(owner={"type": "user"}))),
    ("iszerodataretentionenabled", "isZeroDataRetentionEnabled", RET,
     flip(RET, lambda p: p["projectDataRetention"][0].update(type="none"))),
    ("isspendlimitenforced", "isSpendLimitEnforced", SPEND,
     flip(SPEND, lambda p: p["enforcement"].update(status="inactive"))),
]

BAD = [{}, None, "{}", {"error": True, "status": "Error", "statusCode": 403, "message": "forbidden"},
       {"error": {"message": "Incorrect API key provided", "code": "invalid_api_key"}}, [{"id": "x"}]]


def enriched(body):
    return {"data": body, "validation": {"status": "unknown", "errors": [], "warnings": []}}


# The audit-trail check has no readable "off" in the API: an empty log or a refused call is
# Not evaluated (None), never False. See test_audit_trail_not_evaluated.py.
NO_ANSWER = {"isActivityAuditTrailEnabled": None}


def expected_no(key):
    return NO_ANSWER.get(key, False)


@pytest.mark.parametrize("name,key,good,bad", CASES)
def test_good_and_flip(name, key, good, bad):
    module = load(name)
    for form in (good, enriched(good)):
        assert module.transform(form)["transformedResponse"][key] is True
    for form in (bad, enriched(bad)):
        assert module.transform(form)["transformedResponse"][key] is expected_no(key)


@pytest.mark.parametrize("name,key,good,bad", CASES)
def test_fail_closed(name, key, good, bad):
    module = load(name)
    for body in BAD:
        assert module.transform(body)["transformedResponse"][key] is expected_no(key)
        assert module.transform(enriched(body))["transformedResponse"][key] is expected_no(key)


# A single audit event or SCIM-managed member is proof on its own, and the spend limit is not a list.
PARTIAL = [c for c in CASES if c[1] not in ("isActivityAuditTrailEnabled", "isSCIMProvisioningEnabled", "isSpendLimitEnforced")]


@pytest.mark.parametrize("name,key,good,bad", PARTIAL)
def test_partial_list_fails(name, key, good, bad):
    """A list the pager did not finish (has_more true) never passes."""
    body = copy.deepcopy(good)
    body["has_more"] = True
    assert load(name).transform(body)["transformedResponse"][key] is False


# --- vendor answers that arrive as data (Integration-Service vendorErrorAsResponse) -------------------

def envelope(status, text, body=None):
    """The shape Integration-Service hands over for a vendor error the method opted in to as data."""
    return {"vendorErrorAsResponse": {"status": status, "bodyContains": text,
                                      "body": body if body is not None else {"error": {"message": text + "."}}}}


NO_LIMIT = envelope(404, "No organization spend limit is configured")
NOT_ENABLED = envelope(403, "Data retention controls are not enabled for this organization")
PERMISSION_403 = {"error": True, "status": "Error", "statusCode": 403, "message": "HTTP 403: Forbidden; vendor said: "
                  "You do not have permission to perform this action."}


def reasons(out):
    return " ".join(out["additionalInfo"]["evaluation"]["failReasons"])


@pytest.mark.parametrize("wrap", [lambda b: b, enriched, lambda b: {"apiResponse": b}, lambda b: json.dumps(b)])
def test_spend_limit_404_is_an_answer(wrap):
    out = load("isspendlimitenforced").transform(wrap(NO_LIMIT))
    assert out["transformedResponse"]["isSpendLimitEnforced"] is False
    assert out["transformedResponse"]["spendLimitConfigured"] is False
    assert "no hard spend limit is configured" in reasons(out)
    # an answer, not a failed call: the evaluator must grade it, so the data collection succeeded
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"
    assert "credential" not in reasons(out) and "Retry" not in reasons(out)


@pytest.mark.parametrize("body", [
    envelope(404, "Some other not found"),
    envelope(403, "No organization spend limit is configured"),
    envelope(401, "No organization spend limit is configured"),
    {"error": True, "status": "Error", "statusCode": 404, "message": "HTTP 404: Not Found"},
    PERMISSION_403,
])
def test_spend_limit_other_refusals_stay_refusals(body):
    for form in (body, enriched(body)):
        out = load("isspendlimitenforced").transform(form)
        assert out["transformedResponse"]["isSpendLimitEnforced"] is False
        assert "spendLimitConfigured" not in out["transformedResponse"]
        assert "no hard spend limit is configured" not in reasons(out)


def test_spend_limit_real_limit_still_passes():
    assert load("isspendlimitenforced").transform(SPEND)["transformedResponse"]["isSpendLimitEnforced"] is True


@pytest.mark.parametrize("wrap", [lambda b: b, enriched])
def test_zdr_not_enabled_is_an_answer(wrap):
    body = dict(lst([project("p1")]), orgDataRetention=NOT_ENABLED, projectDataRetention=[envelope(403, "Data retention controls are not enabled for this organization")])
    out = load("iszerodataretentionenabled").transform(wrap(body))
    assert out["transformedResponse"]["isZeroDataRetentionEnabled"] is False
    assert out["transformedResponse"]["dataRetentionControlsEnabled"] is False
    assert "controls are not enabled" in reasons(out)
    assert "credential" not in reasons(out) and "not permitted" not in reasons(out)
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"


@pytest.mark.parametrize("org", [
    PERMISSION_403,
    envelope(403, "Insufficient permissions for this operation"),
    envelope(404, "Data retention controls are not enabled for this organization"),
    {"error": True, "status": "Error", "statusCode": 401, "message": "HTTP 401: Unauthorized"},
])
def test_zdr_real_permission_refusal_stays_a_permission_problem(org):
    body = dict(lst([project("p1")]), orgDataRetention=org, projectDataRetention=[])
    for form in (body, enriched(body)):
        out = load("iszerodataretentionenabled").transform(form)
        assert out["transformedResponse"]["isZeroDataRetentionEnabled"] is False
        assert "dataRetentionControlsEnabled" not in out["transformedResponse"]
        assert "controls are not enabled" not in reasons(out)
    if org is PERMISSION_403:
        assert "not permitted" in reasons(load("iszerodataretentionenabled").transform(body))


def test_zdr_project_row_not_read_never_passes():
    body = dict(RET, projectDataRetention=[envelope(403, "Data retention controls are not enabled for this organization")])
    out = load("iszerodataretentionenabled").transform(body)
    assert out["transformedResponse"]["isZeroDataRetentionEnabled"] is False
    assert "not fully read" in reasons(out)


@pytest.mark.parametrize("wrap", [lambda b: b, enriched])
@pytest.mark.parametrize("empty", [lst([]), lst([], has_more=True), {"object": "list", "data": []}])
def test_audit_log_empty_list_is_not_evaluated(wrap, empty):
    out = load("isactivityaudittrailenabled").transform(wrap(empty))
    assert out["transformedResponse"]["isActivityAuditTrailEnabled"] is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"
    assert "no setting" in out["additionalInfo"]["dataCollection"]["errors"][0]
    assert out["additionalInfo"]["evaluation"]["failReasons"] == []


def test_audit_log_with_events_still_passes_and_junk_is_not_evaluated():
    module = load("isactivityaudittrailenabled")
    good = lst([{"id": "audit_log-1", "type": "api_key.created", "effective_at": NOW - 40 * DAY}])
    assert module.transform(good)["transformedResponse"]["isActivityAuditTrailEnabled"] is True
    junk = module.transform(lst([{"note": "x"}]))
    assert junk["transformedResponse"]["isActivityAuditTrailEnabled"] is None
    assert junk["additionalInfo"]["dataCollection"]["status"] == "error"


def test_the_phrase_is_read_from_the_vendor_body_not_the_echoed_matcher():
    # bodyContains carries the phrase but the vendor body does not: not the documented answer, so a refusal
    echo_only = {"vendorErrorAsResponse": {"status": 404, "bodyContains": "No organization spend limit is configured",
                                           "body": {"error": {"message": "Not found."}}}}
    out = load("isspendlimitenforced").transform(echo_only)
    assert out["transformedResponse"]["isSpendLimitEnforced"] is False
    assert "spendLimitConfigured" not in out["transformedResponse"]
    assert "no hard spend limit is configured" not in reasons(out)
    ret = {"vendorErrorAsResponse": {"status": 403, "bodyContains": "Data retention controls are not enabled for this organization",
                                     "body": {"error": {"message": "Forbidden."}}}}
    out = load("iszerodataretentionenabled").transform(dict(lst([project("p1")]), orgDataRetention=ret, projectDataRetention=[]))
    assert "dataRetentionControlsEnabled" not in out["transformedResponse"]
    assert "controls are not enabled" not in reasons(out)


def test_the_documented_spec_phrase_is_also_the_no_limit_answer():
    spec = envelope(404, "does not have a hard spend limit", {"error": {"message": "The organization does not have a hard spend limit."}})
    out = load("isspendlimitenforced").transform(spec)
    assert out["transformedResponse"]["isSpendLimitEnforced"] is False
    assert out["transformedResponse"]["spendLimitConfigured"] is False
    assert "no hard spend limit is configured" in reasons(out)
