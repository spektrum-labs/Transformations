"""OpenAI Administration API checks, on the documented response schemas (openai-openapi master).
No live admin payload yet: each check has a passing body, a flip that must fail, and the
fail-closed bodies. Prod hands these files the enriched {"data": body, "validation": ...} input
because they read input.get("data"), so both forms are exercised."""
import copy
import importlib.util
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
     lst([{"id": "audit_log-1", "type": "login.succeeded", "effective_at": NOW - DAY}]), lst([])),
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


@pytest.mark.parametrize("name,key,good,bad", CASES)
def test_good_and_flip(name, key, good, bad):
    module = load(name)
    for form in (good, enriched(good)):
        assert module.transform(form)["transformedResponse"][key] is True
    for form in (bad, enriched(bad)):
        assert module.transform(form)["transformedResponse"][key] is False


@pytest.mark.parametrize("name,key,good,bad", CASES)
def test_fail_closed(name, key, good, bad):
    module = load(name)
    for body in BAD:
        assert module.transform(body)["transformedResponse"][key] is False
        assert module.transform(enriched(body))["transformedResponse"][key] is False


# A single audit event or SCIM-managed member is proof on its own, and the spend limit is not a list.
PARTIAL = [c for c in CASES if c[1] not in ("isActivityAuditTrailEnabled", "isSCIMProvisioningEnabled", "isSpendLimitEnforced")]


@pytest.mark.parametrize("name,key,good,bad", PARTIAL)
def test_partial_list_fails(name, key, good, bad):
    """A list the pager did not finish (has_more true) never passes."""
    body = copy.deepcopy(good)
    body["has_more"] = True
    assert load(name).transform(body)["transformedResponse"][key] is False
