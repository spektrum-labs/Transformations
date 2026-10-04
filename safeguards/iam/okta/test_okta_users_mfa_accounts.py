"""Okta - Application isMFAEnforcedForUsers / isMFAEnabled: the finding names active users with no MFA factor (#101).

Both verdicts come from the four policy reads (signOnPolicies, signOnRules, accessPolicies, accessRules) and never
change. When the isMFAEnforcedForUsersAccounts workflow also merges the active users (`users`) and, per user, the
factor list (`userFactors`), the first reason names the active users with no ACTIVE factor: at most 20, then
"and N more".
inputSummary.affectedAccounts carries at most 50, with the full count in affectedAccountCount. Synthetic data only
(x.test logins, zero-filled ids). Each case runs as plain Python and in the Token-Service sandbox replica.
"""
import copy
import importlib.util
import json
import pathlib

import pytest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]
TAG = "okta101usersapp"
KEY = "isMFAEnforcedForUsers"
SCOPE = "Okta (active users)"

try:
    import RestrictedPython  # noqa: F401
    _spec = importlib.util.spec_from_file_location("restricted_sandbox_" + TAG, ROOT / "tools" / "restricted_sandbox.py")
    _sandbox = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_sandbox)
    load_code = _sandbox.load
except ImportError:
    def load_code(code, filename):
        ns = {"__name__": TAG + "_sandbox"}
        exec(compile(code, filename, "exec"), ns)
        return ns

MODES = ["python", "sandbox"]


def namespace(mode):
    path = HERE / "ismfaenforcedforusers.py"
    if mode == "sandbox":
        return load_code(path.read_text(), "<transformation>")
    spec = importlib.util.spec_from_file_location(TAG + "_transform", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return vars(module)


def uid(n):
    return "00000000000000%06d" % n


def login(n):
    return "user%04d@x.test" % n


def factor(n, factor_type="push", status="ACTIVE", owner=None):
    owner = n if owner is None else owner
    return {"id": "fac%06d" % n, "factorType": factor_type, "status": status,
            "_links": {"self": {"href": "https://example.x.test/api/v1/users/" + uid(owner) + "/factors/f"},
                       "user": {"href": "https://example.x.test/api/v1/users/" + uid(owner)}}}


def user(n, status="ACTIVE"):
    return {"id": uid(n), "status": status, "profile": {"login": login(n), "email": login(n)}}


def policy_reads(mode):
    """The getMfaPolicyRules merge: one ACTIVE app authentication policy with one ALLOW rule (2FA or 1FA)."""
    rule = {"id": "rul000001", "name": "Catch-all Rule", "status": "ACTIVE",
            "actions": {"appSignOn": {"access": "ALLOW", "verificationMethod": {
                "type": "ASSURANCE", "factorMode": mode}}}}
    return {"signOnPolicies": [{"id": "pol000001", "name": "Default Policy", "status": "ACTIVE"}],
            "signOnRules": [[{"id": "rul000002", "name": "Default Rule", "status": "ACTIVE",
                              "actions": {"signon": {"access": "ALLOW", "requireFactor": False}}}]],
            "accessPolicies": [{"id": "pol000002", "name": "Any two factors", "status": "ACTIVE",
                                "_embedded": {"resourceType": "APP"}}],
            "accessRules": [[rule]]}


PASS_POLICIES = policy_reads("2FA")
FAIL_POLICIES = policy_reads("1FA")


def merged(policies, specs, **extra):
    """specs: list of (n, factor list or error record). The shape IS's workflow merge produces."""
    out = copy.deepcopy(policies)
    out.update({"users": [user(n) for n, x in specs], "userFactors": [x for n, x in specs]})
    out.update(extra)
    return out


def standard(policies=FAIL_POLICIES):
    return merged(policies, [
        (1, [factor(1, "push")]),                         # enrolled
        (2, []),                                          # nothing enrolled: affected
        (3, [factor(3, "sms", "INACTIVE")]),              # inactive factor only: affected
        (4, [factor(4, "webauthn"), factor(4, "sms", "PENDING_ACTIVATION")]),  # enrolled
    ])


def error_record(n, status=403):
    return {"error": True, "statusCode": status, "item": uid(n), "errorType": "vendorError"}


def verdict(res):
    return res["transformedResponse"], res["additionalInfo"]["dataCollection"]


def reasons(res):
    ev = res["additionalInfo"]["evaluation"]
    return ev["failReasons"] + ev["passReasons"]


def summary(res):
    return res["additionalInfo"]["transformation"]["inputSummary"]


def strip_time(res):
    res = copy.deepcopy(res)
    res["additionalInfo"]["metadata"].pop("evaluatedAt", None)
    return res


@pytest.fixture(params=MODES)
def ns(request):
    return namespace(request.param)


@pytest.fixture
def run(ns):
    return ns["transform"]


def account_line(res):
    lines = [r for r in reasons(res) if SCOPE in r]
    assert len(lines) <= 1
    return lines[0] if lines else None


def test_no_new_input_is_unchanged(run):
    for body in (PASS_POLICIES, FAIL_POLICIES, [], {}, None, "not json", {"error": True}):
        res = run(copy.deepcopy(body))
        assert account_line(res) is None
        assert "affectedAccounts" not in summary(res)
    assert reasons(run(copy.deepcopy(FAIL_POLICIES)))[0] == FAIL_FIRST


FAIL_FIRST = "Identity Engine: 0 of 1 allowing sign-on rules require two factors across 1 policies"
PASS_FIRST = "Identity Engine: 1 of 1 allowing sign-on rules require two factors across 1 policies"


def test_verdict_on_merge_equals_policy_reads(run):
    for policies in (PASS_POLICIES, FAIL_POLICIES, {}, {"errorCode": "E0000006"}):
        bare = run(copy.deepcopy(policies))
        for body in (standard(policies), merged(policies, []), merged(policies, [(1, error_record(1))])):
            res = run(copy.deepcopy(body))
            assert verdict(res) == verdict(bare)
            assert res["additionalInfo"]["validation"] == bare["additionalInfo"]["validation"]


def test_wrapped_merge(run):
    for wrapper in ("data", "apiResponse", "response"):
        bare = run({wrapper: copy.deepcopy(FAIL_POLICIES)})
        res = run({wrapper: standard()})
        assert verdict(res) == verdict(bare)
        assert summary(res)["affectedAccounts"] == [login(2), login(3)]


def test_names_users_without_an_active_factor_on_fail(run):
    res = run(standard())
    assert res["transformedResponse"][KEY] is False
    first = res["additionalInfo"]["evaluation"]["failReasons"][0]
    assert res["transformedResponse"]["isMFAEnabled"] is False
    assert first.startswith(FAIL_FIRST + "; " + SCOPE + ": 2 of 4 active users read have no ACTIVE MFA")
    assert login(2) in first and login(3) in first
    assert login(1) not in first and login(4) not in first
    assert "false positive" in first
    assert summary(res)["affectedAccounts"] == [login(2), login(3)]
    assert summary(res)["affectedAccountCount"] == 2


def test_pass_names_affected_and_clean_pass_names_no_one(run):
    res = run(standard(PASS_POLICIES))
    assert res["transformedResponse"][KEY] is True
    assert res["transformedResponse"]["isMFAEnabled"] is True
    assert res["additionalInfo"]["evaluation"]["passReasons"][0].startswith(PASS_FIRST + "; " + SCOPE + ": 2 of 4")
    clean = run(merged(PASS_POLICIES, [(1, [factor(1)]), (2, [factor(2, "webauthn")])]))
    assert account_line(clean) is None
    assert summary(clean)["affectedAccounts"] == [] and summary(clean)["affectedAccountCount"] == 0


def test_inactive_user_record_is_not_judged(run):
    body = merged(FAIL_POLICIES, [(1, []), (2, [])])
    body["users"][1]["status"] = "SUSPENDED"
    res = run(body)
    assert SCOPE + ": 1 of 1 active users read" in account_line(res)
    assert summary(res)["affectedAccounts"] == [login(1)]


def test_item_error_records_are_counted_not_named(run):
    body = merged(FAIL_POLICIES, [(1, []), (2, error_record(2)), (3, error_record(3, 429)), (4, [factor(4)])],
                  itemErrors=2, iterateStats={"userFactors": {"itemsTotal": 4, "itemsProcessed": 4, "itemErrors": 2,
                                                              "iterateTruncated": False}})
    res = run(body)
    line = account_line(res)
    assert SCOPE + ": 1 of 2 active users read" in line
    assert "2 users could not be read" in line
    assert login(2) not in line and login(3) not in line
    assert summary(res)["affectedAccounts"] == [login(1)]


def test_vendor_error_slot_is_unread(run):
    vendor = {"vendorErrorAsResponse": {"status": 403, "bodyContains": "E0000006", "body": {"errorCode": "E0000006"}}}
    res = run(merged(FAIL_POLICIES, [(1, []), (2, vendor)]))
    assert "1 user could not be read" in account_line(res)
    assert summary(res)["affectedAccounts"] == [login(1)]


def test_reported_item_errors_raise_the_unread_count(run):
    res = run(merged(FAIL_POLICIES, [(1, []), (2, [factor(2)])], itemErrors=5))
    assert "5 users could not be read" in account_line(res)


def test_truncated_read_names_only_what_was_read(run):
    specs = [(n, [] if n % 2 else [factor(n)]) for n in range(1, 1201)]
    body = merged(FAIL_POLICIES, specs)
    body["userFactors"] = body["userFactors"][:1000]
    body["iterateTruncated"] = True
    body["iterateStats"] = {"userFactors": {"itemsTotal": 1200, "itemsProcessed": 1000, "itemErrors": 0,
                                            "iterateTruncated": True}}
    res = run(body)
    line = account_line(res)
    assert SCOPE + ": 500 of 1,000 active users read" in line
    assert "only the first 1,000 of 1,200 active users were checked" in line
    assert " and 480 more" in line
    assert summary(res)["affectedAccountCount"] == 500
    assert len(summary(res)["affectedAccounts"]) == 50
    assert login(1001) not in json.dumps(res)


def test_more_than_1000_users_judges_the_first_1000(run):
    specs = [(n, []) for n in range(1, 1003)]
    res = run(merged(FAIL_POLICIES, specs))
    line = account_line(res)
    assert "1,000 of 1,000 active users read" in line
    assert "only the first 1,000 of 1,002" in line
    assert login(1001) not in json.dumps(res)


def test_exactly_1000_users_says_more_may_exist(run):
    res = run(merged(FAIL_POLICIES, [(n, [factor(n)]) for n in range(1, 1001)]))
    assert "1,000 active users were read, the most the user list read returns" in account_line(res)


@pytest.mark.parametrize("change", ["short", "long", "short_no_stats", "processed_mismatch"])
def test_mismatched_lengths_name_no_one(run, change):
    body = standard()
    if change == "short":
        body["userFactors"] = body["userFactors"][:3]
    elif change == "long":
        body["userFactors"].append([])
    elif change == "short_no_stats":
        body["userFactors"] = body["userFactors"][:2]
        body["iterateStats"] = {"userFactors": {"itemsProcessed": 2}}
    else:
        body["userFactors"] = body["userFactors"][:2]
        body["iterateTruncated"] = True
        body["iterateStats"] = {"userFactors": {"itemsProcessed": 3, "iterateTruncated": True}}
    res = run(body)
    assert SCOPE + ": accounts not named, the per-user factor results do not line up" in account_line(res)
    assert "affectedAccounts" not in summary(res)


@pytest.mark.parametrize("change,why", [
    ("other_owner", "does not belong to that user"),
    ("record_other_user", "belongs to another user"),
    ("users_error", "the active user list was not read (Okta answered HTTP 403)"),
    ("users_garbage", "the active user list was not read"),
    ("users_empty", "Okta returned no active users"),
    ("no_id", "carries no id"),
    ("factors_missing", "the per-user factor read is missing"),
    ("factors_garbage", "the per-user factor read was not returned"),
    ("all_unread", "no active user's factor list was read"),
])
def test_partial_or_missing_reads_name_no_one(run, change, why):
    body = standard()
    if change == "other_owner":
        body["userFactors"][1] = [factor(2, owner=3)]
    elif change == "record_other_user":
        body["userFactors"][1] = error_record(3)
    elif change == "users_error":
        body["users"] = {"vendorErrorAsResponse": {"status": 403, "bodyContains": "E0000006"}}
    elif change == "users_garbage":
        body["users"] = "x"
    elif change == "users_empty":
        body["users"] = []
    elif change == "no_id":
        body["users"][2].pop("id")
    elif change == "factors_missing":
        body.pop("userFactors")
    elif change == "factors_garbage":
        body["userFactors"] = 7
    else:
        body["userFactors"] = [error_record(n) for n in range(1, 5)]
    res = run(body)
    line = account_line(res)
    assert (SCOPE + ": accounts not named") in line and why in line
    assert "affectedAccounts" not in summary(res)
    assert verdict(res) == verdict(run(copy.deepcopy(FAIL_POLICIES)))


def test_json_text_input(run):
    res = run(json.dumps(standard()))
    assert summary(res)["affectedAccounts"] == [login(2), login(3)]


def test_transformation_error_branch_is_untouched(run):
    res = run(b"\xff")
    assert res["transformedResponse"] == {KEY: False, "isMFAEnabled": False}
    assert account_line(res) is None


def test_guard_returns_a_broken_response_unchanged(ns):
    guard = ns["with_user_accounts"]
    body = standard()
    for broken in [{}, {"transformedResponse": {KEY: False}},
                   {"transformedResponse": {KEY: False}, "additionalInfo": {"evaluation": {"failReasons": "x"}}},
                   {"transformedResponse": {KEY: False},
                    "additionalInfo": {"evaluation": {"failReasons": [7], "passReasons": []},
                                       "transformation": {"inputSummary": {}}}},
                   {"transformedResponse": {KEY: False},
                    "additionalInfo": {"evaluation": {"failReasons": ["x"], "passReasons": []},
                                       "transformation": {"inputSummary": None}}},
                   [], None, "x"]:
        before = json.dumps(broken, sort_keys=True)
        out = guard(broken, body, KEY)
        assert out is broken
        assert json.dumps(out, sort_keys=True) == before


def test_guard_survives_garbage_input(ns):
    response = ns["transform"](copy.deepcopy(FAIL_POLICIES))
    before = strip_time(response)
    for raw in [None, 7, "not json", b"\xff", {"users": None}, {"users": [None]}, {"users": [{"id": 7}]}]:
        out = ns["with_user_accounts"](copy.deepcopy(response), raw, KEY)
        if account_line(out) is None:
            assert strip_time(out) == before
        else:
            assert verdict(out) == verdict(response)


def test_name_cap(run):
    res = run(merged(FAIL_POLICIES, [(n, []) for n in range(1, 61)]))
    line = account_line(res)
    assert login(20) in line and login(21) not in line and " and 40 more" in line
    assert summary(res)["affectedAccountCount"] == 60 and len(summary(res)["affectedAccounts"]) == 50
