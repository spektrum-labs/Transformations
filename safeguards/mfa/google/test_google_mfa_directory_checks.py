"""Google - MFA: the five Directory users.list checks (getUserMFAStatus).

Bodies follow the documented user resource (developers.google.com/admin-sdk/directory/reference/rest/v1/users)
inside the envelope the paged method returns, with booleans as the strings "True"/"False" as Google - MFA
bodies arrive. Each check: pass, flip, suspended/archived excluded, and every read that proves nothing
(truncated, empty, None, error envelope, refusal, not JSON) is Not evaluated: the criterion is None and
dataCollection.status is "error" with a reason, never False."""
import copy
import importlib.util
import json
import pathlib

HERE = pathlib.Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location("google_mfa_dir_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ENFORCE = load("workspaceusermfaenforcementpercentage")
ENROL = load("workspaceusermfaenrollmentpercentage")
EXEMPT = load("mfaexemptuseraccountscount")
ADMIN_COUNT = load("superadminaccountswithoutmfacount")
ADMIN_ALL = load("issuperadminmfafullyenforced")

ERROR = {"error": True, "message": "Integration execution error: HTTP 403: Forbidden"}
GOOGLE_ERROR = {"error": {"code": 403, "status": "PERMISSION_DENIED",
                          "message": "Request had insufficient authentication scopes."}}


def user(email, admin="False", enrolled="True", enforced="True", suspended="False", archived="False"):
    return {"kind": "admin#directory#user", "id": email, "primaryEmail": email, "isAdmin": admin,
            "isEnrolledIn2Sv": enrolled, "isEnforcedIn2Sv": enforced, "suspended": suspended, "archived": archived}


GOOD = {"apiResponse": {"kind": "admin#directory#users", "users": [
    user("a@x.test", admin="True"), user("b@x.test"), user("c@x.test"),
    user("gone@x.test", enrolled="False", enforced="False", suspended="True"),
    user("old@x.test", admin="True", enforced="False", archived="True")]}}


def with_user(body, **kw):
    out = copy.deepcopy(body)
    out["apiResponse"]["users"].append(user("new@x.test", **kw))
    return out


def value(module, body):
    out = module.transform(body)
    return out["transformedResponse"][module.CRITERIA_KEY], out["additionalInfo"]["dataCollection"]["status"]


def test_all_good():
    assert value(ENFORCE, GOOD) == (100.0, "success")
    assert value(ENROL, GOOD) == (100.0, "success")
    assert value(EXEMPT, GOOD) == (0, "success")
    assert value(ADMIN_COUNT, GOOD) == (0, "success")
    assert value(ADMIN_ALL, GOOD) == (True, "success")


def test_flips():
    unenforced = with_user(GOOD, enforced="False")
    assert value(ENFORCE, unenforced) == (75.0, "success")
    assert value(ENROL, unenforced) == (100.0, "success")
    assert value(EXEMPT, unenforced) == (0, "success")
    exempt = with_user(GOOD, enrolled="False", enforced="False")
    assert value(ENROL, exempt) == (75.0, "success")
    assert value(EXEMPT, exempt) == (1, "success")
    bad_admin = with_user(GOOD, admin="True", enforced="False")
    assert value(ADMIN_COUNT, bad_admin) == (1, "success")
    assert value(ADMIN_ALL, bad_admin) == (False, "success")


def test_real_booleans_and_bare_list():
    body = [dict(u, isAdmin=u["isAdmin"] == "True", isEnforcedIn2Sv=u["isEnforcedIn2Sv"] == "True",
                 isEnrolledIn2Sv=u["isEnrolledIn2Sv"] == "True", suspended=u["suspended"] == "True",
                 archived=u["archived"] == "True") for u in GOOD["apiResponse"]["users"]]
    assert value(ENFORCE, body) == (100.0, "success")
    assert value(ADMIN_ALL, body) == (True, "success")


def test_no_admin_is_not_measured():
    body = {"users": [user("b@x.test")]}
    assert value(ADMIN_COUNT, body) == (None, "error")
    assert value(ADMIN_ALL, body) == (None, "error")
    only_suspended_admin = {"users": [user("gone@x.test", admin="True", suspended="True"), user("b@x.test")]}
    assert value(ADMIN_COUNT, only_suspended_admin) == (None, "error")
    assert value(ADMIN_ALL, only_suspended_admin) == (None, "error")


def assert_not_evaluated(module, body):
    """Every criterion key None, and the failure on the channel Token-Service reads."""
    out = module.transform(body)
    inner = out["transformedResponse"]
    assert module.CRITERIA_KEY in inner, body
    assert all(got is None for got in inner.values()), (module.CRITERIA_KEY, body, inner)
    collection = out["additionalInfo"]["dataCollection"]
    assert collection["status"] == "error", (module.CRITERIA_KEY, body)
    assert collection["errors"] and all(isinstance(e, str) and e for e in collection["errors"]), body


ALL_MODULES = (ENFORCE, ENROL, EXEMPT, ADMIN_COUNT, ADMIN_ALL)
REFUSAL = {"statusCode": 403, "message": "Forbidden"}
INTEGRATION_ERROR_STATUS = {"status": "error", "message": "Integration execution error"}


def test_not_measured_inputs():
    truncated = copy.deepcopy(GOOD)
    truncated["apiResponse"]["nextPageToken"] = "next"
    for body in [truncated, {}, None, "", "{}", ERROR, GOOGLE_ERROR, REFUSAL, INTEGRATION_ERROR_STATUS,
                 {"apiResponse": GOOGLE_ERROR}, {"users": None}, {"users": "x"}, [], "[]", "null",
                 "<html/>", "<html>Bad gateway</html>", "not json at all", b"\x00not json", b"", 42]:
        for module in ALL_MODULES:
            assert_not_evaluated(module, body)
    scope = ADMIN_ALL.transform(GOOGLE_ERROR)["additionalInfo"]["dataCollection"]["errors"][0]
    assert "scope not granted" in scope


def test_empty_user_list_is_not_evaluated():
    for body in ({"users": []}, {"apiResponse": {"kind": "admin#directory#users", "users": []}}, []):
        for module in ALL_MODULES:
            assert_not_evaluated(module, body)
    all_suspended = {"users": [user("gone@x.test", admin="True", suspended="True"),
                               user("old@x.test", archived="True")]}
    for module in ALL_MODULES:
        assert_not_evaluated(module, all_suspended)


def test_truncated_user_list_is_not_evaluated_even_when_a_finding_is_visible():
    # An unread page could change the answer either way, so a partial list proves nothing.
    truncated = with_user(GOOD, admin="True", enforced="False")
    truncated["apiResponse"]["nextPageToken"] = "next"
    for module in ALL_MODULES:
        assert_not_evaluated(module, truncated)
        assert_not_evaluated(module, json.dumps(truncated))
