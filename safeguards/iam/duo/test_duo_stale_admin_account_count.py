"""Duo staleAdminAccountCount: enabled Duo console admins with no sign-in in 90+ days.

Input is the getStaleAdminAccounts workflow output (getAdmins, merge: true, no output key): {"response": [...]}
or the bare list once Token-Service drills the wrapper away. Used by both Duo and Duo MSP. Every case runs as
plain Python and in the Token-Service sandbox replica. "Now" is pinned by replacing utc_now. Synthetic data only
(x.test, zero-filled ids).
"""
import importlib.util
import json
import pathlib
from datetime import datetime, timedelta, timezone

import pytest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]
TAG = "duo_stale_admins"
PATH = HERE / "staleAdminAccountCount.py"
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

MODES = ["python", "sandbox"]


def load(mode):
    if mode == "sandbox":
        ns = load_code(PATH.read_text(), "<transformation>")
        ns["utc_now"] = lambda: NOW
        return ns["transform"]
    spec = importlib.util.spec_from_file_location(TAG, PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.utc_now = lambda: NOW
    return module.transform


def ts(days_ago):
    return None if days_ago is None else int((NOW - timedelta(days=days_ago)).timestamp())


def admin(n, status="Active", last=10, created=400, role="Administrator"):
    return {"admin_id": "DE%018d" % n, "name": "Admin %03d" % n, "email": "admin%03d@x.test" % n, "role": role,
            "status": status, "last_login": ts(last), "created": ts(created)}


def wrap(admins):
    return {"response": admins, "stat": "OK"}


def out_of(out):
    return out["transformedResponse"]["staleAdminAccountCount"]


def info(out):
    return out["additionalInfo"]


def unevaluated(out, needle):
    assert out_of(out) is None
    assert info(out)["dataCollection"]["status"] == "error"
    text = " ".join(info(out)["dataCollection"]["errors"])
    assert needle in text, text


@pytest.mark.parametrize("mode", MODES)
def test_all_fresh_passes(mode):
    out = load(mode)(wrap([admin(1, role="Owner"), admin(2, last=89)]))
    assert out_of(out) == 0
    first = info(out)["evaluation"]["passReasons"][0]
    assert first.startswith("Duo: 0 of 2 enabled Duo console admins have no sign-in in 90+ days")


@pytest.mark.parametrize("mode", MODES)
def test_stale_admin_counted_and_named(mode):
    out = load(mode)(wrap([admin(1, role="Owner"), admin(2, last=91), admin(3, last=400, role="Read-only")]))
    assert out_of(out) == 2
    first = info(out)["evaluation"]["failReasons"][0]
    assert first == ("Duo: 2 of 3 enabled Duo console admins have no sign-in in 90+ days: admin002@x.test, "
                     "admin003@x.test")
    summary = info(out)["transformation"]["inputSummary"]
    assert summary["affectedAccounts"] == ["admin002@x.test", "admin003@x.test"]
    assert summary["affectedAccountCount"] == 2
    assert summary["adminCount"] == 3


@pytest.mark.parametrize("mode", MODES)
def test_bare_list_and_string_input(mode):
    t = load(mode)
    admins = [admin(1), admin(2, last=120)]
    assert out_of(t(admins)) == 1
    assert out_of(t(json.dumps(wrap(admins)))) == 1
    assert out_of(t({"apiResponse": wrap(admins)})) == 1


@pytest.mark.parametrize("mode", MODES)
def test_never_signed_in(mode):
    out = load(mode)(wrap([admin(1), admin(2, last=None, created=100), admin(3, status="Pending Activation",
                                                                            last=None, created=5)]))
    assert out_of(out) == 1
    summary = info(out)["transformation"]["inputSummary"]
    assert summary["affectedAccounts"] == ["admin002@x.test"]
    assert summary["neverSignedInAdminCount"] == 2


@pytest.mark.parametrize("mode", MODES)
def test_disabled_and_expired_excluded(mode):
    out = load(mode)(wrap([admin(1), admin(2, status="Disabled", last=500), admin(3, status="Expired", last=None)]))
    assert out_of(out) == 0
    summary = info(out)["transformation"]["inputSummary"]
    assert summary["disabledAdmins"] == ["admin002@x.test", "admin003@x.test"]
    assert summary["disabledAdminCount"] == 2


@pytest.mark.parametrize("mode", MODES)
def test_cap(mode):
    out = load(mode)(wrap([admin(n, last=200) for n in range(1, 56)]))
    assert out_of(out) == 55
    first = info(out)["evaluation"]["failReasons"][0]
    assert first.count("@x.test") == 20 and first.endswith(" and 35 more")
    assert len(info(out)["transformation"]["inputSummary"]["affectedAccounts"]) == 50


@pytest.mark.parametrize("mode", MODES)
def test_403_marker_and_fail_body(mode):
    t = load(mode)
    marker = {"vendorErrorAsResponse": {"status": 403, "bodyContains": "40301",
                                        "body": {"stat": "FAIL", "code": 40301, "message": "Access forbidden"}}}
    unevaluated(t(marker), "Grant administrators - Read")
    unevaluated(t({"response": marker}), "HTTP 403")
    unevaluated(t({"stat": "FAIL", "code": 40103, "message": "Invalid signature"}), "returned an error")


@pytest.mark.parametrize("mode", MODES)
def test_truncated(mode):
    t = load(mode)
    data = wrap([admin(1)])
    data["paginationTruncated"] = True
    unevaluated(t(data), "paginationTruncated is set")
    data = wrap([admin(1)])
    data["metadata"] = {"next_offset": 300, "total_objects": 900}
    unevaluated(t(data), "next_offset remains")


@pytest.mark.parametrize("mode", MODES)
def test_empty_unrecognised_and_bad_dates(mode):
    t = load(mode)
    unevaluated(t(wrap([])), "no Duo administrator objects")
    unevaluated(t({}), "no Duo administrator objects")
    unevaluated(t([{"user_id": "DU1", "username": "x"}]), "not a Duo administrator object")
    bad = admin(1)
    bad["last_login"] = "yesterday"
    unevaluated(t(wrap([bad])), "unreadable last_login")
    unevaluated(t(wrap([admin(1, last=None, created=None)])), "created date cannot be read")
    unevaluated(t(wrap([admin(1, status="Locked")])), "unrecognised status")
    unevaluated(t(wrap([admin(1, status="Disabled")])), "no enabled Duo administrator")
