"""OpenAI Administration API checks, on the documented response schemas (openai-openapi 2.3.0).

Each check has a passing body, a flip that must fail, and the no-evidence batteries. The two
halves are asserted separately and deliberately:

  * a FLIP is a measured failure -- the body was read, the posture is wrong -> False;
  * a no-evidence body measured nothing -> None AND dataCollection.status "error".

Asserting only the value would pass either way, and that is exactly how the hardcoded
"dataCollection": {"status": "success"} in these files survived until now. Token-Service reads
the status and nothing else when it decides whether a criterion was evaluated, so a test that
does not assert the status does not test the thing that matters.

Prod hands these files the enriched {"data": body, "validation": ...} input because they read
input.get("data"), so both forms are exercised. Synthetic data only.
"""
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


def bare_user(uid, role="reader"):
    """A user object exactly as OpenAI's published example and Labs' live body carry one.

    is_scim_managed is in the User schema but not in its `required` list, and neither the
    vendor's example nor a real organization's response includes it.
    """
    return {"object": "organization.user", "id": uid, "name": uid, "email": uid + "@example.invalid",
            "role": role, "added_at": NOW}


def group(gid, scim=False, spelling="is_scim_managed"):
    """A GroupResponse as GET /v1/organization/groups returns it.

    is_scim_managed and group_type are both in that schema's `required` list.
    """
    g = {"id": gid, "name": gid, "created_at": NOW - 30 * DAY, "group_type": "group"}
    g[spelling] = scim
    return g


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


class Poisoned(dict):
    """A non-empty object whose every read raises, to drive transform()'s own except path.

    A battery of bodies, however broad, cannot reach a branch that only the transform's own
    failure enters. This is a different instrument, not a different body.
    """

    def __init__(self):
        super().__init__(poisoned=True)

    def boom(self, *args, **kwargs):
        raise RuntimeError("poisoned read")

    get = __getitem__ = __contains__ = keys = items = values = __iter__ = boom

    def __len__(self):
        return 1


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

# Three distinct routes to a non-answer, because a replay of one proves nothing about the
# others: a vendor refusal envelope, a body with nothing in it, and the transform's own crash.
NO_EVIDENCE = [
    ("empty_dict", lambda: {}),
    ("none", lambda: None),
    ("empty_json_string", lambda: "{}"),
    ("refusal_403_relay", lambda: {"error": True, "status": "Error", "statusCode": 403, "message": "forbidden"}),
    ("refusal_vendor_401", lambda: {"error": {"message": "Incorrect API key provided", "code": "invalid_api_key"}}),
    ("bare_list", lambda: [{"id": "x"}]),
    ("poisoned", Poisoned),
]


def enriched(body):
    return {"data": body, "validation": {"status": "unknown", "errors": [], "warnings": []}}


def assert_not_measured(out, key):
    """The pair, not the value. None under a "success" status is still graded as a FAIL."""
    assert out["transformedResponse"][key] is None
    collection = out["additionalInfo"]["dataCollection"]
    assert collection["status"] == "error"
    assert collection["errors"]
    assert all(isinstance(e, str) and e for e in collection["errors"])


@pytest.mark.parametrize("name,key,good,bad", CASES)
def test_good_and_flip(name, key, good, bad):
    module = load(name)
    for form in (good, enriched(good)):
        assert module.transform(form)["transformedResponse"][key] is True
    for form in (bad, enriched(bad)):
        out = module.transform(form)
        assert out["transformedResponse"][key] is False
        assert out["additionalInfo"]["dataCollection"]["status"] == "success"


@pytest.mark.parametrize("name,key,good,bad", CASES)
@pytest.mark.parametrize("shape", [s[0] for s in NO_EVIDENCE])
def test_no_evidence_is_not_a_finding(name, key, good, bad, shape):
    """A body that proves nothing reaches the evaluator as not evaluated, not as a red."""
    module = load(name)
    body = dict(NO_EVIDENCE)[shape]
    assert_not_measured(module.transform(body()), key)
    assert_not_measured(module.transform(enriched(body())), key)


# A single audit event or SCIM-managed member is proof on its own, and the spend limit is not
# a list, so a partial read does not change those answers.
PARTIAL = [c for c in CASES if c[1] not in ("isActivityAuditTrailEnabled", "isSCIMProvisioningEnabled", "isSpendLimitEnforced")]


@pytest.mark.parametrize("name,key,good,bad", PARTIAL)
def test_partial_list_is_not_measured(name, key, good, bad):
    """A list the pager did not finish is a sample, not an estate: it measures nothing."""
    body = copy.deepcopy(good)
    body["has_more"] = True
    assert_not_measured(load(name).transform(body), key)


# ---------------------------------------------------------------------------------------
# isSCIMProvisioningEnabled reads SCIM state off the object the vendor guarantees it on.
# ---------------------------------------------------------------------------------------

SCIM = "isSCIMProvisioningEnabled"


def scim_transform(body):
    return load("isscimprovisioningenabled").transform(body)


def test_group_list_with_a_scim_managed_group_passes():
    out = scim_transform(lst([group("g1", scim=True), group("g2", scim=False)]))
    assert out["transformedResponse"][SCIM] is True
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"


def test_group_list_with_no_scim_managed_group_fails():
    out = scim_transform(lst([group("g1"), group("g2")]))
    assert out["transformedResponse"][SCIM] is False
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"


def test_group_summary_spelling_is_read_too():
    """Group.scim_managed and GroupResponse.is_scim_managed are the same fact, two spellings."""
    out = scim_transform(lst([group("g1", scim=True, spelling="scim_managed")]))
    assert out["transformedResponse"][SCIM] is True


def test_partial_group_list_with_no_scim_group_is_not_measured():
    """"None of the groups on page one" is a sample, not a finding."""
    assert_not_measured(scim_transform(lst([group("g1")], has_more=True)), SCIM)


def test_partial_group_list_with_a_scim_group_still_passes():
    """One SCIM-managed group is proof on its own; the unread pages cannot withdraw it."""
    assert scim_transform(lst([group("g1", scim=True)], has_more=True))["transformedResponse"][SCIM] is True


def test_user_list_without_the_optional_field_is_not_measured():
    """The defect this replaces: OpenAI omits is_scim_managed on users, and omission is not false.

    Labs' own live /v1/organization/users body carries exactly these fields on every user. The
    previous implementation answered False here, which no customer could ever clear.
    """
    assert_not_measured(scim_transform(lst([bare_user("u1", "owner"), bare_user("u2")])), SCIM)


def test_user_list_that_does_report_the_field_is_still_measured():
    """Where OpenAI does send the optional field, it is a real measurement in both directions."""
    assert scim_transform(lst([user("u1", "owner")]))["transformedResponse"][SCIM] is True
    assert scim_transform(lst([user("u1", "owner", scim=False)]))["transformedResponse"][SCIM] is False


def test_group_list_that_reports_no_scim_field_is_not_measured():
    """is_scim_managed is required on GroupResponse, so a group without it is an unknown shape."""
    assert_not_measured(scim_transform(lst([{"id": "g1", "name": "g1", "group_type": "group"}])), SCIM)
