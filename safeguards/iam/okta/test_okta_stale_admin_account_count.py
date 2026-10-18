"""Okta staleAdminAccountCount: enabled admins with no sign-in in 90+ days.

Input is the getStaleAdminAccounts workflow output {"adminAssignees": <iam/assignees/users body>, "users": [...]}.
Every case runs as plain Python and in the Token-Service sandbox replica (tools/restricted_sandbox.py), against
both copies (iam/okta and 86ded564-...), which must stay byte-identical. "Now" is pinned by replacing utc_now.
Synthetic data only (x.test, zero-filled ids).
"""
import importlib.util
import json
import pathlib
from datetime import datetime, timedelta, timezone

import pytest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]
TAG = "okta_stale_admins"
PATHS = {
    "iam/okta": HERE / "staleAdminAccountCount.py",
    "86ded564": ROOT / "safeguards" / "86ded564-522a-4c9b-9106-365e4cbdec7d" / "staleadminaccountcount.py",
}
NOW = datetime(2026, 10, 1, 12, 0, 0, tzinfo=timezone.utc)

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

CASES = [(copy, mode) for copy in PATHS for mode in ("python", "sandbox")]


def load(copy, mode):
    path = PATHS[copy]
    if mode == "sandbox":
        ns = load_code(path.read_text(), "<transformation>")
        ns["utc_now"] = lambda: NOW
        return ns["transform"]
    spec = importlib.util.spec_from_file_location(TAG + "_" + copy.replace("/", "_"), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.utc_now = lambda: NOW
    return module.transform


def iso(days_ago):
    return (NOW - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def uid(n):
    return "00u%017d" % n


def user(n, status="ACTIVE", last=10, created=400):
    return {"id": uid(n), "status": status, "created": iso(created),
            "lastLogin": None if last is None else iso(last),
            "profile": {"login": "admin%03d@x.test" % n, "email": "admin%03d@x.test" % n}}


def assignees(*ns, next_href=None):
    body = {"value": [{"id": uid(n), "orn": "orn:okta:directory:00o0000000000000000:users:" + uid(n),
                       "_links": {}} for n in ns],
            "_links": {"self": {"href": "https://tenant.x.test/api/v1/iam/assignees/users"}}}
    if next_href is not None:
        body["_links"]["next"] = {"href": next_href}
    return body


def body(admin_ns, users):
    return {"adminAssignees": assignees(*admin_ns), "users": users}


def out_of(out):
    return out["transformedResponse"]["staleAdminAccountCount"]


def info(out):
    return out["additionalInfo"]


def unevaluated(out, needle):
    assert out_of(out) is None
    assert out["transformedResponse"]["adminCount"] is None
    assert info(out)["dataCollection"]["status"] == "error"
    text = " ".join(info(out)["dataCollection"]["errors"])
    assert needle in text, text


def test_copies_are_byte_identical():
    assert PATHS["iam/okta"].read_bytes() == PATHS["86ded564"].read_bytes()


def test_shared_helpers_identical_across_vendors():
    marker = "# ---------------------------------------------------------------- "
    files = [PATHS["iam/okta"], ROOT / "safeguards" / "mfa" / "azure" / "staleadminaccountcount.py",
             ROOT / "safeguards" / "iam" / "duo" / "staleAdminAccountCount.py"]
    blocks = []
    for f in files:
        text = f.read_text()
        start = text.index(marker + "shared helpers")
        end = text.index(marker, start + len(marker))
        blocks.append(text[start:end])
    assert blocks[0] == blocks[1] == blocks[2]


@pytest.mark.parametrize("copy,mode", CASES)
def test_all_fresh_passes(copy, mode):
    out = load(copy, mode)(body([1, 2], [user(1), user(2, last=89), user(3, last=400)]))
    assert out_of(out) == 0
    assert out["transformedResponse"]["adminCount"] == 2
    assert info(out)["dataCollection"]["status"] == "success"
    first = info(out)["evaluation"]["passReasons"][0]
    assert first.startswith("Okta: 0 of 2 enabled Okta admins (users holding an admin role) have no sign-in in 90+ days")
    assert info(out)["transformation"]["inputSummary"]["affectedAccountCount"] == 0
    assert info(out)["evaluation"]["failReasons"] == []


@pytest.mark.parametrize("copy,mode", CASES)
def test_stale_admin_is_counted_and_named(copy, mode):
    out = load(copy, mode)(body([1, 2], [user(1), user(2, last=120), user(3, last=400)]))
    assert out_of(out) == 1
    first = info(out)["evaluation"]["failReasons"][0]
    assert first == ("Okta: 1 of 2 enabled Okta admins (users holding an admin role) have no sign-in in 90+ days: "
                     "admin002@x.test")
    summary = info(out)["transformation"]["inputSummary"]
    assert summary["affectedAccounts"] == ["admin002@x.test"]
    assert summary["adminCount"] == 2
    assert summary["evaluatedAt"] == NOW.isoformat()
    # a non-admin who never signs in is not Okta's admin finding
    assert "admin003" not in json.dumps(out)


@pytest.mark.parametrize("copy,mode", CASES)
def test_never_signed_in_old_admin_is_stale_new_one_is_not(copy, mode):
    users = [user(1), user(2, last=None, created=200), user(3, last=None, created=30)]
    out = load(copy, mode)(body([1, 2, 3], users))
    assert out_of(out) == 1
    summary = info(out)["transformation"]["inputSummary"]
    assert summary["affectedAccounts"] == ["admin002@x.test"]
    assert summary["neverSignedInAdminCount"] == 2


@pytest.mark.parametrize("copy,mode", CASES)
def test_disabled_admins_excluded_and_listed(copy, mode):
    users = [user(1), user(2, status="SUSPENDED", last=300), user(3, status="DEPROVISIONED", last=None)]
    out = load(copy, mode)(body([1, 2, 3], users))
    assert out_of(out) == 0
    summary = info(out)["transformation"]["inputSummary"]
    assert summary["disabledAdmins"] == ["admin002@x.test", "admin003@x.test"]
    assert summary["disabledAdminCount"] == 2
    assert summary["adminCount"] == 1


@pytest.mark.parametrize("copy,mode", CASES)
def test_name_cap_20_in_reason_50_in_summary(copy, mode):
    ns = list(range(1, 62))
    users = [user(n, last=200) for n in ns] + [user(99)]
    out = load(copy, mode)(body(ns + [99], users))
    assert out_of(out) == 61
    first = info(out)["evaluation"]["failReasons"][0]
    assert first.count("@x.test") == 20
    assert first.endswith(" and 41 more")
    summary = info(out)["transformation"]["inputSummary"]
    assert len(summary["affectedAccounts"]) == 50
    assert summary["affectedAccountCount"] == 61


@pytest.mark.parametrize("copy,mode", CASES)
def test_missing_admin_in_user_list_is_partial_read(copy, mode):
    out = load(copy, mode)(body([1, 2], [user(1)]))
    unevaluated(out, "not in the user list")


@pytest.mark.parametrize("copy,mode", CASES)
def test_unread_next_link_is_truncated(copy, mode):
    data = {"adminAssignees": assignees(1, next_href="https://tenant.x.test/api/v1/iam/assignees/users?after=x"),
            "users": [user(1)]}
    unevaluated(load(copy, mode)(data), "not read to the end")


@pytest.mark.parametrize("copy,mode", CASES)
def test_pagination_truncated_flag(copy, mode):
    data = body([1], [user(1)])
    data["adminAssignees"]["_links"]["next"] = {"href": None, "truncated": True, "scannedCount": 10000}
    unevaluated(load(copy, mode)(data), "truncated is set")
    data = body([1], [user(1)])
    data["paginationTruncated"] = True
    unevaluated(load(copy, mode)(data), "paginationTruncated is set")


@pytest.mark.parametrize("copy,mode", CASES)
def test_403_marker_and_error_body(copy, mode):
    data = {"adminAssignees": {"vendorErrorAsResponse": {"status": 403, "bodyContains": "E0000006",
                                                          "body": {"errorCode": "E0000006"}}},
            "users": [user(1)]}
    unevaluated(load(copy, mode)(data), "HTTP 403")
    data = {"adminAssignees": {"errorCode": "E0000006", "errorSummary": "You do not have permission"},
            "users": [user(1)]}
    unevaluated(load(copy, mode)(data), "returned an error")


@pytest.mark.parametrize("copy,mode", CASES)
def test_empty_and_missing_inputs(copy, mode):
    t = load(copy, mode)
    unevaluated(t({}), "missing")
    unevaluated(t(None), "not an object")
    unevaluated(t({"adminAssignees": {"value": []}, "users": [user(1)]}), "no admin role holders")
    unevaluated(t({"adminAssignees": assignees(1), "users": []}), "no users")
    unevaluated(t({"statusCode": 403, "error": "Forbidden"}), "missing")


@pytest.mark.parametrize("copy,mode", CASES)
def test_unparseable_dates_and_status(copy, mode):
    t = load(copy, mode)
    bad = user(1)
    bad["lastLogin"] = "last tuesday"
    unevaluated(t(body([1], [bad])), "unreadable lastLogin")
    never = user(1, last=None)
    never["created"] = None
    unevaluated(t(body([1], [never])), "created date cannot be read")
    odd = user(1, status="WEIRD")
    unevaluated(t(body([1], [odd])), "unrecognised status")


@pytest.mark.parametrize("copy,mode", CASES)
def test_all_admins_disabled_is_unevaluated(copy, mode):
    out = load(copy, mode)(body([1], [user(1, status="SUSPENDED")]))
    unevaluated(out, "no enabled admin")


@pytest.mark.parametrize("copy,mode", CASES)
def test_wrapped_and_string_input(copy, mode):
    t = load(copy, mode)
    data = body([1, 2], [user(1), user(2, last=95)])
    assert out_of(t({"apiResponse": data})) == 1
    assert out_of(t(json.dumps(data))) == 1
