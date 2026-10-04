"""Okta isSAMLEnforced: every active user-facing app in Okta signs users in through SAML or OIDC federation.

Input is the listApplications body (GET /api/v1/apps, Link-header paging), bare or under the Integration-Service /
Token-Service wrappers. Every case runs as plain Python and in the Token-Service sandbox replica
(tools/restricted_sandbox.py). Synthetic data only (x.test, zero-filled ids, generic labels).
"""
import importlib.util
import json
import pathlib
import sys

import pytest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PATH = HERE / "issamlenforced.py"
TAG = "okta_issamlenforced"
KEY = "isSAMLEnforced"

try:
    import RestrictedPython  # noqa: F401
    _spec = importlib.util.spec_from_file_location("restricted_sandbox_" + TAG, ROOT / "tools" / "restricted_sandbox.py")
    _sandbox = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_sandbox)
    load_code = _sandbox.load
except ImportError:  # pragma: no cover - CI installs RestrictedPython
    def load_code(code, filename):
        ns = {"__name__": TAG + "_sandbox"}
        exec(compile(code, filename, "exec"), ns)
        return ns

MODES = ["python", "sandbox"]


def load(mode):
    if mode == "sandbox":
        return load_code(PATH.read_text(), "<transformation>")["transform"]
    spec = importlib.util.spec_from_file_location(TAG + "_python", PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def app(n, mode="SAML_2_0", status="ACTIVE", name=None, service=False):
    body = {"id": "0oa%017d" % n, "name": name or ("x_test_app_%d" % n), "label": "App %03d" % n,
            "status": status, "signOnMode": mode,
            "_links": {"self": {"href": "https://tenant.x.test/api/v1/apps/0oa%017d" % n}}}
    if service:
        body["settings"] = {"oauthClient": {"application_type": "service"}}
    elif mode == "OPENID_CONNECT":
        body["settings"] = {"oauthClient": {"application_type": "web"}}
    return body


def builtins():
    return [app(901, "OPENID_CONNECT", name="saasure"), app(902, "OPENID_CONNECT", name="okta_enduser"),
            app(903, "AUTO_LOGIN", name="okta_browser_plugin"), app(904, "SAML_2_0", name="okta_flow_sso")]


def verdict(out):
    return out["transformedResponse"][KEY]


def info(out):
    return out["additionalInfo"]


def summary(out):
    return info(out)["transformation"]["inputSummary"]


def unevaluated(out, needle):
    assert verdict(out) is None
    assert info(out)["dataCollection"]["status"] == "error"
    text = " ".join(info(out)["dataCollection"]["errors"])
    assert needle in text, text
    assert info(out)["evaluation"]["failReasons"][0].startswith("Not evaluated: ")


# ---------------------------------------------------------------- measured answers

@pytest.mark.parametrize("mode", MODES)
def test_all_federated_passes(mode):
    apps = [app(1, "SAML_2_0"), app(2, "OPENID_CONNECT"), app(3, "WS_FEDERATION"), app(4, "SAML_1_1")] + builtins()
    out = load(mode)(apps)
    assert verdict(out) is True
    assert info(out)["dataCollection"]["status"] == "success"
    first = info(out)["evaluation"]["passReasons"][0]
    assert first.startswith("Okta (apps integrated in Okta): all 4 active user-facing apps sign users in through "
                            "SAML or OIDC federation")
    assert summary(out)["affectedAppCount"] == 0
    assert summary(out)["affectedApps"] == []
    assert summary(out)["federatedAppCount"] == 4


@pytest.mark.parametrize("mode", MODES)
def test_password_apps_fail_and_are_named(mode):
    apps = [app(1, "SAML_2_0"), app(2, "AUTO_LOGIN"), app(3, "BROWSER_PLUGIN"), app(4, "BASIC_AUTH"),
            app(5, "SECURE_PASSWORD_STORE"), app(6, "OPENID_CONNECT")] + builtins()
    out = load(mode)(apps)
    assert verdict(out) is False
    assert info(out)["dataCollection"]["status"] == "success"
    first = info(out)["evaluation"]["failReasons"][0]
    assert first.startswith("Okta (apps integrated in Okta): 4 of 6 active user-facing apps sign users in with a "
                            "password")
    for named in ("App 002 (AUTO_LOGIN)", "App 003 (BROWSER_PLUGIN)", "App 004 (BASIC_AUTH)",
                  "App 005 (SECURE_PASSWORD_STORE)"):
        assert named in first
    assert "App 001" not in first
    assert summary(out)["affectedAppCount"] == 4
    assert summary(out)["affectedApps"] == ["App 002 (AUTO_LOGIN)", "App 003 (BROWSER_PLUGIN)",
                                            "App 004 (BASIC_AUTH)", "App 005 (SECURE_PASSWORD_STORE)"]
    assert info(out)["evaluation"]["recommendations"]


@pytest.mark.parametrize("mode", MODES)
def test_names_at_most_50_then_total(mode):
    apps = [app(n, "AUTO_LOGIN") for n in range(1, 61)] + [app(100, "SAML_2_0")]
    out = load(mode)(apps)
    assert verdict(out) is False
    first = info(out)["evaluation"]["failReasons"][0]
    assert "60 of 61" in first
    assert first.endswith("App 050 (AUTO_LOGIN) and 10 more")
    assert "App 051" not in first
    assert len(summary(out)["affectedApps"]) == 50
    assert summary(out)["affectedAppCount"] == 60


@pytest.mark.parametrize("mode", MODES)
def test_builtin_password_app_is_not_judged(mode):
    out = load(mode)([app(1, "SAML_2_0"), app(903, "AUTO_LOGIN", name="okta_browser_plugin")])
    assert verdict(out) is True
    findings = " ".join(info(out)["evaluation"]["additionalFindings"])
    assert "Okta built-in app(s) not judged" in findings
    assert "App 903" in findings


@pytest.mark.parametrize("mode", MODES)
def test_inactive_bookmark_and_service_apps_are_not_judged(mode):
    apps = [app(1, "SAML_2_0"), app(2, "AUTO_LOGIN", status="INACTIVE"), app(3, "BOOKMARK"),
            app(4, "OPENID_CONNECT", service=True)]
    out = load(mode)(apps)
    assert verdict(out) is True
    s = summary(out)
    assert (s["activeUserFacingAppCount"], s["inactiveAppCount"], s["bookmarkAppCount"], s["serviceAppCount"]) == \
        (1, 1, 1, 1)
    findings = " ".join(info(out)["evaluation"]["additionalFindings"])
    assert "bookmark app(s) not judged" in findings and "App 003" in findings
    assert "OAuth service app(s) not judged" in findings
    assert "inactive app(s) not judged" in findings


@pytest.mark.parametrize("mode", MODES)
def test_one_password_app_among_many_fails(mode):
    apps = [app(n, "OPENID_CONNECT") for n in range(1, 200)] + [app(500, "BASIC_AUTH")]
    out = load(mode)(apps)
    assert verdict(out) is False
    assert summary(out)["affectedApps"] == ["App 500 (BASIC_AUTH)"]


@pytest.mark.parametrize("mode", MODES)
def test_just_under_the_read_cap_is_judged(mode):
    out = load(mode)([app(n, "SAML_2_0") for n in range(1, 2000)])
    assert verdict(out) is True
    assert summary(out)["appsRead"] == 1999


# ---------------------------------------------------------------- wrappers

@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("wrap", ["json", "bytes", "apiResponse", "data_string", "is_handler", "response_data"])
def test_wrapped_bodies_read_the_same(mode, wrap):
    apps = [app(1, "SAML_2_0"), app(2, "AUTO_LOGIN")]
    body = {
        "json": json.dumps(apps),
        "bytes": json.dumps(apps).encode("utf-8"),
        "apiResponse": {"apiResponse": apps},
        "data_string": {"data": {"apiResponse": json.dumps(apps)}},
        "is_handler": {"status": "success", "data": apps, "response_metadata": {"status_code": 200}},
        "response_data": {"_response_data": apps, "status_code": 200},
    }[wrap]
    out = load(mode)(body)
    assert verdict(out) is False
    assert summary(out)["affectedApps"] == ["App 002 (AUTO_LOGIN)"]


# ---------------------------------------------------------------- fail closed

@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("body,needle", [
    ([], "returned no apps"),
    ({"apiResponse": []}, "returned no apps"),
    ({}, "not a list of apps"),
    (None, "not a list of apps"),
    ("", "not a list of apps"),
    ({"hello": "world"}, "not a list of apps"),
    ({"errorCode": "E0000006", "errorSummary": "You do not have permission to perform the requested action"},
     "Okta returned an error"),
    ({"statusCode": 403, "error": "Forbidden"}, "Okta returned an error"),
    ({"status_code": 401, "_response_data": {"message": "x"}}, "HTTP 401"),
    ({"vendorErrorAsResponse": {"status": 403, "body": "x"}}, "okta.apps.read"),
    ({"vendorErrorAsResponse": {"status": 429, "body": "x"}}, "HTTP 429"),
    ({"error": True, "errorType": "pagination_incomplete", "status": "Error", "statusCode": 429,
      "message": "Pagination stopped at page 3", "pagesRead": 2, "itemsDiscarded": 400}, "Okta returned an error"),
    ({"apiResponse": [app(1)], "response_metadata": {"paginationTruncated": True}}, "paginationTruncated is set"),
    ({"paginationTruncated": True, "_response_data": [app(1)]}, "paginationTruncated is set"),
    ({"data": [app(1)], "pagination": {"truncated": True}}, "truncated is set"),
    ({"data": [app(1)], "_links": {"next": {"href": "https://tenant.x.test/api/v1/apps?after=0oa1"}}},
     "next page link remains"),
    ([app(1), "garbage"], "is not an object"),
    ([app(1), app(2, status="PENDING")], "unrecognised status"),
    ([app(1), app(2, status=None)], "unrecognised status"),
    ([app(1), app(2, mode="SOMETHING_NEW")], "unrecognised sign-on mode"),
    ([app(1), app(2, mode=None)], "unrecognised sign-on mode"),
    ("not json", "Transformation error"),
])
def test_no_evidence_is_not_evaluated(mode, body, needle):
    unevaluated(load(mode)(body), needle)


@pytest.mark.parametrize("mode", MODES)
def test_only_builtin_service_bookmark_or_inactive_apps_is_not_evaluated(mode):
    apps = builtins() + [app(1, "OPENID_CONNECT", service=True), app(2, "BOOKMARK"), app(3, "SAML_2_0", status="INACTIVE")]
    out = load(mode)(apps)
    unevaluated(out, "no active user-facing app")
    assert summary(out)["activeUserFacingAppCount"] == 0


@pytest.mark.parametrize("mode", MODES)
def test_a_read_at_the_cap_may_be_cut_and_is_not_evaluated(mode):
    unevaluated(load(mode)([app(n, "SAML_2_0") for n in range(1, 2001)]), "may have been cut at maxPages")


@pytest.mark.parametrize("mode", MODES)
def test_fail_closed_battery_never_true(mode):
    sys.path.insert(0, str(ROOT / "tools"))
    try:
        import check_fail_closed
    finally:
        sys.path.pop(0)
    transform = load(mode)
    battery = check_fail_closed.NO_EVIDENCE
    items = battery.items() if isinstance(battery, dict) else battery
    for entry in items:
        body = entry[1] if isinstance(entry, tuple) else entry
        for form in (body, json.dumps(body)):
            assert verdict(transform(form)) is not True
