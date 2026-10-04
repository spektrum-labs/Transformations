"""Okta isAdminMFAPhishingResistant: the finding names the affected admins (#101, the Okta admin gap).

The verdict comes from the org factor list (GET /api/v1/org/factors) and never changes. When the
isAdminMFAPhishingResistantAccounts workflow also merges the admin list (adminAssignees) and, per admin, the user
record (adminUsers) and the factor list (adminFactors), the first reason names the admins with no ACTIVE FIDO2/WebAuthn,
FIDO U2F, Okta FastPass or smart card factor (the set the verdict counts): at most 20, then "and N more", in one
line that names the tool and its scope.
inputSummary.affectedAccounts carries at most 50, with the full count in affectedAccountCount. A missing, error,
truncated or out-of-line per-admin read names no one and says the account read was partial. Synthetic data only
(x.test logins, zero-filled ids). Each case runs as plain Python and in the Token-Service sandbox replica.
"""
import copy
import importlib.util
import pathlib

import pytest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]
TAG = "okta101admin"
KEY = "isAdminMFAPhishingResistant"
SCOPE = "Okta (users holding an Okta admin role)"

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
    path = HERE / "isAdminMFAPhishingResistant.py"
    if mode == "sandbox":
        return load_code(path.read_text(), "<transformation>")
    spec = importlib.util.spec_from_file_location(TAG + "_transform", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return vars(module)


def load(mode):
    return namespace(mode)["transform"]


def uid(n):
    return "00000000000000%06d" % n


def login(n):
    return "admin%03d@x.test" % n


def org(kind):
    """Org factor lists: 'mixed' (FIDO2 and push ACTIVE), 'resistant' (FIDO2 only), 'phishable' (push only)."""
    active = {"mixed": ["webauthn", "push"], "resistant": ["webauthn"], "phishable": ["push"]}[kind]
    out = []
    for factor_type, provider in [("webauthn", "FIDO"), ("u2f", "FIDO"), ("push", "OKTA"), ("sms", "OKTA"),
                                  ("token:software:totp", "OKTA"), ("signed_nonce", "OKTA")]:
        out.append({"factorType": factor_type, "provider": provider,
                    "status": "ACTIVE" if factor_type in active else "INACTIVE"})
    return out


def factor(n, factor_type, status="ACTIVE", owner=None):
    owner = n if owner is None else owner
    return {"id": "fac%06d%s" % (n, factor_type.replace(":", "")), "factorType": factor_type, "status": status,
            "provider": "FIDO" if factor_type in ("webauthn", "u2f") else "OKTA",
            "_links": {"self": {"href": "https://example.x.test/api/v1/users/" + uid(owner) + "/factors/f"},
                       "user": {"href": "https://example.x.test/api/v1/users/" + uid(owner)}}}


def user(n):
    return {"id": uid(n), "status": "ACTIVE", "profile": {"login": login(n), "email": login(n)}}


def merged(kind, admins, capped=False):
    """admins: list of (n, [factor dicts]). The shape IS's workflow merge produces."""
    links = {"self": {"href": "https://example.x.test/api/v1/iam/assignees/users?limit=100"}}
    if capped:
        links["next"] = {"href": None, "truncated": True, "scannedCount": len(admins)}
    return {
        "factors": org(kind),
        "adminAssignees": {"value": [{"id": uid(n), "orn": "orn:x.test:" + str(n)} for n, x in admins],
                           "_links": links},
        "adminUsers": [user(n) for n, x in admins],
        "adminFactors": [fs for n, fs in admins],
    }


def standard(kind="mixed"):
    return merged(kind, [
        (1, [factor(1, "webauthn"), factor(1, "push")]),          # phishing-resistant
        (2, [factor(2, "push")]),                                 # push only: affected
        (3, [factor(3, "webauthn", "INACTIVE"), factor(3, "sms")]),  # inactive key: affected
        (4, []),                                                  # nothing enrolled: affected
        (5, [factor(5, "u2f")]),                                  # FIDO U2F key
    ])


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
def run(request):
    return load(request.param)


@pytest.mark.parametrize("kind", ["mixed", "resistant", "phishable"])
def test_no_new_input_is_unchanged(run, kind):
    bare = run(org(kind))
    wrapped = run({"factors": org(kind)})
    assert strip_time(bare) == strip_time(wrapped)
    assert "affectedAccounts" not in summary(bare)
    assert not any(SCOPE in r for r in reasons(bare))


@pytest.mark.parametrize("kind", ["mixed", "resistant", "phishable"])
def test_verdict_identical_with_admin_reads(run, kind):
    assert verdict(run(standard(kind))) == verdict(run(org(kind)))


def test_mixed_org_names_affected_admins(run):
    res = run(standard("mixed"))
    assert res["transformedResponse"][KEY] is None
    first = res["additionalInfo"]["evaluation"]["failReasons"][0]
    assert SCOPE + ": 3 of 5 admins have no ACTIVE phishing-resistant factor" in first
    assert "(2 with only phishable factors such as push, 1 with no active factor)" in first
    assert ": admin002@x.test, admin003@x.test, admin004@x.test;" in first
    assert "admin001@x.test" not in first and "admin005@x.test" not in first
    assert summary(res)["affectedAccounts"] == ["admin002@x.test", "admin003@x.test", "admin004@x.test"]
    assert summary(res)["affectedAccountCount"] == 3
    # dataCollection errors keep today's message only
    assert res["additionalInfo"]["dataCollection"] == run(org("mixed"))["additionalInfo"]["dataCollection"]


def test_push_only_org_fail_names_everyone_without_a_key(run):
    res = run(standard("phishable"))
    assert res["transformedResponse"][KEY] is False
    assert "admin002@x.test, admin003@x.test, admin004@x.test" in res["additionalInfo"]["evaluation"]["failReasons"][0]


def test_clean_pass_names_no_one(run):
    body = merged("resistant", [(1, [factor(1, "webauthn")]), (2, [factor(2, "u2f"), factor(2, "push")])])
    res = run(body)
    assert res["transformedResponse"][KEY] is True
    assert res["additionalInfo"]["evaluation"]["passReasons"] == run(org("resistant"))[
        "additionalInfo"]["evaluation"]["passReasons"]
    assert summary(res)["affectedAccounts"] == [] and summary(res)["affectedAccountCount"] == 0


def test_pass_with_an_affected_admin_says_so(run):
    body = merged("resistant", [(1, [factor(1, "webauthn")]), (2, [factor(2, "push")])])
    res = run(body)
    assert res["transformedResponse"][KEY] is True
    assert SCOPE + ": 1 of 2 admins" in res["additionalInfo"]["evaluation"]["passReasons"][0]
    assert "admin002@x.test" in res["additionalInfo"]["evaluation"]["passReasons"][0]


@pytest.mark.parametrize("factor_type", ["signed_nonce", "smart_card", "webauthn", "u2f"])
def test_every_type_the_verdict_counts_is_not_named(run, factor_type):
    # Okta FastPass (signed_nonce) and smart card count exactly as the org-level verdict counts them.
    body = merged("mixed", [(1, [factor(1, factor_type)]), (2, [factor(2, factor_type), factor(2, "push")]),
                            (3, [factor(3, "push")])])
    res = run(body)
    assert summary(res)["affectedAccounts"] == ["admin003@x.test"]
    assert "admin001@x.test" not in reasons(res)[0] and "admin002@x.test" not in reasons(res)[0]


def test_per_admin_set_is_the_verdict_set():
    for mode in MODES:
        ns = namespace(mode)
        assert ns["ADMIN_PHISH_RESISTANT_TYPES"] is ns["PHISH_RESISTANT_TYPES"]


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("broken", ["no_info", "no_evaluation", "no_summary", "reasons_not_list", "not_dict"])
def test_with_accounts_never_changes_a_response_it_cannot_read(mode, broken):
    ns = namespace(mode)
    good = ns["transform"](standard("phishable"))
    named = ns["named_accounts"](standard("phishable"))
    assert named is not None
    response = copy.deepcopy(good)
    if broken == "no_info":
        del response["additionalInfo"]
    elif broken == "no_evaluation":
        del response["additionalInfo"]["evaluation"]
    elif broken == "no_summary":
        del response["additionalInfo"]["transformation"]["inputSummary"]
    elif broken == "reasons_not_list":
        response["additionalInfo"]["evaluation"]["failReasons"] = "x"
    else:
        response = ["not", "a", "dict"]
    before = copy.deepcopy(response)
    out = ns["with_accounts"](response, named, False)
    assert out == before
    if isinstance(out, dict):
        assert out["transformedResponse"] == good["transformedResponse"]


@pytest.mark.parametrize("mode", MODES)
def test_with_accounts_ignores_a_broken_named_block(mode):
    ns = namespace(mode)
    response = ns["transform"](org("phishable"))
    before = copy.deepcopy(response)
    for named in [{}, {"accounts": {}, "line": "x"}, {"accounts": {"read": True}, "line": None}, "x"]:
        assert ns["with_accounts"](response, named, False) == before


def test_inactive_and_pending_keys_do_not_count(run):
    body = merged("mixed", [(1, [factor(1, "webauthn", "INACTIVE")]),
                            (2, [factor(2, "u2f", "PENDING_ACTIVATION")])])
    res = run(body)
    assert summary(res)["affectedAccounts"] == ["admin001@x.test", "admin002@x.test"]
    assert "(0 with only phishable factors such as push, 2 with no active factor)" in reasons(res)[0]


def assert_partial(res, kind, why):
    assert verdict(res) == verdict(load("python")(org(kind)))
    first = reasons(res)[0]
    assert SCOPE + ": accounts not named, the per-admin account read was partial (" + why in first
    assert "affectedAccounts" not in summary(res) and "affectedAccountCount" not in summary(res)
    assert "@x.test" not in first


def forbidden(status, code):
    return {"vendorErrorAsResponse": {"status": status, "bodyContains": code,
                                      "body": {"errorCode": code, "errorSummary": "denied"}}}


def test_403_on_one_admins_factors_names_no_one(run):
    body = standard("mixed")
    body["adminFactors"][1] = forbidden(403, "E0000006")
    assert_partial(run(body), "mixed", "an admin's factor list was not read")


def test_403_on_one_admins_user_record_names_no_one(run):
    body = standard("phishable")
    body["adminUsers"][0] = forbidden(403, "E0000006")
    assert_partial(run(body), "phishable", "an admin's user record was not read")


def test_truncated_per_admin_results_name_no_one(run):
    body = standard("mixed")
    body["adminFactors"] = body["adminFactors"][:3]
    assert_partial(run(body), "mixed", "per-admin results for 3 of 5 admins")


def test_per_admin_results_missing_name_no_one(run):
    body = standard("resistant")
    del body["adminFactors"]
    assert_partial(run(body), "resistant", "the per-admin user or factor results are missing")


def test_out_of_line_factor_list_names_no_one(run):
    body = standard("mixed")
    body["adminFactors"][0], body["adminFactors"][1] = body["adminFactors"][1], body["adminFactors"][0]
    assert_partial(run(body), "mixed", "an admin's factor list does not belong to that admin")


def test_garbage_per_admin_results_name_no_one(run):
    body = standard("mixed")
    body["adminFactors"] = "not a list"
    assert_partial(run(body), "mixed", "the per-admin user or factor results are missing")


def test_more_than_100_admins_is_capped_and_partial(run):
    body = merged("phishable", [(n, [factor(n, "push")]) for n in range(1, 101)], capped=True)
    res = run(body)
    assert res["transformedResponse"][KEY] is False
    first = res["additionalInfo"]["evaluation"]["failReasons"][0]
    assert SCOPE + ": 100 of 100 admins" in first
    assert "admin020@x.test and 80 more" in first and "admin021@x.test" not in first
    assert "the account read is partial: the admin list is capped at 100 and more admins exist" in first
    assert len(summary(res)["affectedAccounts"]) == 50 and summary(res)["affectedAccountCount"] == 100


def test_capped_clean_pass_still_says_partial(run):
    body = merged("resistant", [(n, [factor(n, "webauthn")]) for n in range(1, 101)], capped=True)
    res = run(body)
    assert res["transformedResponse"][KEY] is True
    assert "the admin list is capped at 100" in res["additionalInfo"]["evaluation"]["passReasons"][0]


def test_admin_list_403_names_no_one(run):
    body = standard("mixed")
    body["adminAssignees"] = forbidden(403, "E0000006")
    body["adminUsers"] = forbidden(404, "E0000007")
    body["adminFactors"] = forbidden(404, "E0000007")
    res = run(body)
    assert verdict(res) == verdict(run(org("mixed")))
    assert SCOPE + ": accounts not named, the admin role assignments were not read (Okta answered HTTP 403)" in \
        reasons(res)[0]
    assert "affectedAccounts" not in summary(res)


def test_empty_admin_list_names_no_one(run):
    body = merged("phishable", [])
    res = run(body)
    assert SCOPE + ": accounts not named, Okta returned no admin role assignments" in reasons(res)[0]


def test_no_factor_list_stays_fail_closed_and_names_no_one(run):
    body = standard("mixed")
    del body["factors"]
    res = run(body)
    assert verdict(res) == verdict(run({}))
    assert res["transformedResponse"][KEY] is None
    assert not any(SCOPE in r for r in reasons(res))


def test_wrapped_body_unwraps_like_the_bare_one(run):
    assert strip_time(run({"apiResponse": standard("mixed")})) == strip_time(run(standard("mixed")))
