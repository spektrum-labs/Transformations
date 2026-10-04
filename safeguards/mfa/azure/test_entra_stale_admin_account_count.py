"""Microsoft Entra ID staleAdminAccountCount: enabled active role holders with no successful sign-in in 90+ days.

Input is the getStaleAdminAccounts workflow output {"roleAssignments": <Graph body>, "users": <Graph body>}, as the
Azure AD app registration and One-Click definitions produce it. Every case runs as plain Python and in the
Token-Service sandbox replica, against both copies (mfa/azure and d9b6f27a-...), which must stay byte-identical.
"Now" is pinned by replacing utc_now. Synthetic data only (x.test, zero-filled ids).
"""
import importlib.util
import json
import pathlib
from datetime import datetime, timedelta, timezone

import pytest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]
TAG = "entra_stale_admins"
PATHS = {
    "mfa/azure": HERE / "staleadminaccountcount.py",
    "d9b6f27a": ROOT / "safeguards" / "d9b6f27a-2e67-4b55-a09e-0784c5de9abd" / "staleadminaccountcount.py",
}
NOW = datetime(2026, 10, 1, 12, 0, 0, tzinfo=timezone.utc)
GLOBAL_ADMIN = "62e90394-69f5-4237-9190-012177145e10"

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
    return None if days_ago is None else (NOW - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def oid(n):
    return "00000000-0000-0000-0000-%012d" % n


def user(n, enabled=True, success=10, interactive="same", non_interactive=None, created=400):
    activity = {
        "lastSuccessfulSignInDateTime": iso(success),
        "lastSignInDateTime": iso(success if interactive == "same" else interactive),
        "lastNonInteractiveSignInDateTime": iso(non_interactive),
    }
    return {"id": oid(n), "userPrincipalName": "admin%03d@x.test" % n, "displayName": "Admin %03d" % n,
            "accountEnabled": enabled, "userType": "Member", "createdDateTime": iso(created),
            "signInActivity": activity}


def assignment(n, kind="#microsoft.graph.user"):
    principal = {"id": oid(n)}
    if kind:
        principal["@odata.type"] = kind
    return {"id": "assign-%d" % n, "principalId": oid(n), "roleDefinitionId": GLOBAL_ADMIN,
            "directoryScopeId": "/", "principal": principal}


def body(assignments, users):
    return {"roleAssignments": {"@odata.context": "https://graph.microsoft.com/v1.0/$metadata#x",
                                "value": assignments},
            "users": {"@odata.context": "https://graph.microsoft.com/v1.0/$metadata#users", "value": users}}


def out_of(out):
    return out["transformedResponse"]["staleAdminAccountCount"]


def info(out):
    return out["additionalInfo"]


def unevaluated(out, needle):
    assert out_of(out) is None
    assert info(out)["dataCollection"]["status"] == "error"
    text = " ".join(info(out)["dataCollection"]["errors"])
    assert needle in text, text


def test_copies_are_byte_identical():
    assert PATHS["mfa/azure"].read_bytes() == PATHS["d9b6f27a"].read_bytes()


@pytest.mark.parametrize("copy,mode", CASES)
def test_all_fresh_passes_and_states_scope(copy, mode):
    out = load(copy, mode)(body([assignment(1), assignment(2)], [user(1), user(2, success=60), user(3, success=500)]))
    assert out_of(out) == 0
    passes = info(out)["evaluation"]["passReasons"]
    assert passes[0].startswith("Microsoft Entra ID: 0 of 2 enabled active role holders (users with an active "
                                "directory role assignment) have no successful sign-in in 90+ days")
    assert "PIM-eligible" in passes[1]
    assert info(out)["transformation"]["inputSummary"]["pimEligibleCovered"] is False


@pytest.mark.parametrize("copy,mode", CASES)
def test_stale_role_holder_counted(copy, mode):
    out = load(copy, mode)(body([assignment(1), assignment(2)], [user(1), user(2, success=120)]))
    assert out_of(out) == 1
    fails = info(out)["evaluation"]["failReasons"]
    assert fails[0] == ("Microsoft Entra ID: 1 of 2 enabled active role holders (users with an active directory "
                        "role assignment) have no successful sign-in in 90+ days: admin002@x.test")
    assert "PIM-eligible" in fails[1]


@pytest.mark.parametrize("copy,mode", CASES)
def test_failed_interactive_attempt_does_not_hide_staleness(copy, mode):
    # lastSignInDateTime also counts failed attempts; the successful one decides
    u = user(1, success=200, interactive=1)
    out = load(copy, mode)(body([assignment(1)], [u, user(2)]))
    assert out_of(out) == 1


@pytest.mark.parametrize("copy,mode", CASES)
def test_fallback_to_later_of_interactive_and_non_interactive(copy, mode):
    fresh = user(1, success=None, interactive=200, non_interactive=5)
    stale = user(2, success=None, interactive=150, non_interactive=100)
    out = load(copy, mode)(body([assignment(1), assignment(2)], [fresh, stale]))
    assert out_of(out) == 1
    assert info(out)["transformation"]["inputSummary"]["affectedAccounts"] == ["admin002@x.test"]


@pytest.mark.parametrize("copy,mode", CASES)
def test_never_signed_in_old_admin_is_stale(copy, mode):
    old = user(1, success=None, interactive=None, created=365)
    old["signInActivity"] = None
    new = user(2, success=None, interactive=None, created=20)
    out = load(copy, mode)(body([assignment(1), assignment(2)], [old, new]))
    assert out_of(out) == 1
    summary = info(out)["transformation"]["inputSummary"]
    assert summary["affectedAccounts"] == ["admin001@x.test"]
    assert summary["neverSignedInAdminCount"] == 2


@pytest.mark.parametrize("copy,mode", CASES)
def test_disabled_and_non_user_holders(copy, mode):
    assignments = [assignment(1), assignment(2), assignment(7, "#microsoft.graph.servicePrincipal")]
    out = load(copy, mode)(body(assignments, [user(1), user(2, enabled=False, success=400)]))
    assert out_of(out) == 0
    summary = info(out)["transformation"]["inputSummary"]
    assert summary["disabledAdmins"] == ["admin002@x.test"]
    assert summary["nonUserRoleHolderCount"] == 1
    assert summary["groupRoleAssignmentCount"] == 0
    assert summary["adminCount"] == 1
    assert "not expanded" not in json.dumps(info(out)["evaluation"])


@pytest.mark.parametrize("copy,mode", CASES)
def test_group_held_assignments_with_zero_stale_are_unevaluated(copy, mode):
    # group principal: not in the users list, typed by the expand; must not read as a missing user (partial read)
    assignments = [assignment(1), assignment(8, "#microsoft.graph.group"), assignment(9, "#microsoft.graph.group")]
    out = load(copy, mode)(body(assignments, [user(1)]))
    unevaluated(out, "2 role assignments are through groups; members not checked")
    assert "not in the user list" not in " ".join(info(out)["dataCollection"]["errors"])
    assert info(out)["transformation"]["inputSummary"]["groupRoleAssignmentCount"] == 2
    # groups only, no direct user holder
    out = load(copy, mode)(body([assignment(8, "#microsoft.graph.group")], [user(1)]))
    unevaluated(out, "1 role assignments are through groups; members not checked")


@pytest.mark.parametrize("copy,mode", CASES)
def test_group_held_assignments_with_stale_user_still_fail(copy, mode):
    assignments = [assignment(1), assignment(2), assignment(8, "#microsoft.graph.group")]
    out = load(copy, mode)(body(assignments, [user(1), user(2, success=200)]))
    assert out_of(out) == 1
    first = info(out)["evaluation"]["failReasons"][0]
    assert first.startswith("Microsoft Entra ID: 1 of 2 enabled active role holders")
    assert "admin002@x.test" in first
    assert first.endswith("(1 group-held role assignment(s) were not expanded; their members are not checked)")
    assert info(out)["transformation"]["inputSummary"]["groupRoleAssignmentCount"] == 1


@pytest.mark.parametrize("copy,mode", CASES)
def test_duplicate_assignments_count_once(copy, mode):
    second = assignment(1)
    second["roleDefinitionId"] = "fe930be7-5e62-47db-91af-98c3a49a38b1"
    out = load(copy, mode)(body([assignment(1), second], [user(1, success=100)]))
    assert out_of(out) == 1
    assert out["transformedResponse"]["adminCount"] == 1


@pytest.mark.parametrize("copy,mode", CASES)
def test_missing_principal_is_partial_read(copy, mode):
    unevaluated(load(copy, mode)(body([assignment(1), assignment(2)], [user(1)])), "not in the user list")
    untyped = assignment(3, kind=None)
    unevaluated(load(copy, mode)(body([assignment(1), untyped], [user(1)])), "principal type")


@pytest.mark.parametrize("copy,mode", CASES)
def test_licence_403_marker(copy, mode):
    graph_error = {"error": {"code": "Authentication_RequestFromNonPremiumTenantOrB2CTenant",
                             "message": "Neither tenant is B2C or tenant doesn't have premium license"}}
    data = body([assignment(1)], [user(1)])
    data["users"] = {"vendorErrorAsResponse": {"status": 403, "bodyContains": "premium", "body": graph_error}}
    out = load(copy, mode)(data)
    unevaluated(out, "Entra ID P1")
    data["users"]["vendorErrorAsResponse"]["body"] = json.dumps(graph_error)
    unevaluated(load(copy, mode)(data), "Entra ID P1")


@pytest.mark.parametrize("copy,mode", CASES)
def test_permission_403_marker_on_either_key(copy, mode):
    denied = {"vendorErrorAsResponse": {"status": 403, "bodyContains": "Authorization_RequestDenied",
                                        "body": {"error": {"code": "Authorization_RequestDenied",
                                                           "message": "Insufficient privileges"}}}}
    data = body([assignment(1)], [user(1)])
    data["users"] = denied
    unevaluated(load(copy, mode)(data), "Authorization_RequestDenied")
    data = body([assignment(1)], [user(1)])
    data["roleAssignments"] = denied
    unevaluated(load(copy, mode)(data), "Authorization_RequestDenied")
    data = body([assignment(1)], [user(1)])
    data["users"] = {"vendorErrorAsResponse": {"status": 429, "bodyContains": "error", "body": "{}"}}
    unevaluated(load(copy, mode)(data), "HTTP 429")


@pytest.mark.parametrize("copy,mode", CASES)
def test_truncated_reads(copy, mode):
    data = body([assignment(1)], [user(1)])
    data["users"]["@odata.nextLink"] = "https://graph.microsoft.com/v1.0/users?$skiptoken=x"
    unevaluated(load(copy, mode)(data), "@odata.nextLink remains")
    data = body([assignment(1)], [user(1)])
    data["roleAssignments"]["paginationTruncated"] = True
    unevaluated(load(copy, mode)(data), "paginationTruncated is set")
    data = body([assignment(1)], [user(1)])
    data["response_metadata"] = {"paginationTruncated": True}
    unevaluated(load(copy, mode)(data), "paginationTruncated is set")


@pytest.mark.parametrize("copy,mode", CASES)
def test_list_of_pages_is_read_whole(copy, mode):
    data = {"roleAssignments": [{"value": [assignment(1)]}, {"value": [assignment(2)]}],
            "users": [{"value": [user(1)]}, {"value": [user(2, success=95)]}]}
    assert out_of(load(copy, mode)(data)) == 1
    data["users"][1]["@odata.nextLink"] = "https://graph.microsoft.com/v1.0/users?$skiptoken=y"
    unevaluated(load(copy, mode)(data), "@odata.nextLink remains")


@pytest.mark.parametrize("copy,mode", CASES)
def test_error_empty_and_unparseable(copy, mode):
    t = load(copy, mode)
    unevaluated(t({}), "missing")
    unevaluated(t({"roleAssignments": {"error": {"code": "Request_Throttled", "message": "slow down"}},
                   "users": {"value": [user(1)]}}), "Request_Throttled")
    unevaluated(t(body([assignment(1)], [])), "no users")
    unevaluated(t(body([], [user(1)])), "no user holds an active directory role")
    no_activity = user(1)
    del no_activity["signInActivity"]
    unevaluated(t(body([assignment(1)], [no_activity])), "no signInActivity")
    bad = user(1)
    bad["signInActivity"]["lastSuccessfulSignInDateTime"] = "not-a-date"
    unevaluated(t(body([assignment(1)], [bad])), "cannot be read")
    nocreated = user(1, success=None, interactive=None)
    nocreated["createdDateTime"] = None
    unevaluated(t(body([assignment(1)], [nocreated])), "createdDateTime cannot be read")
    noflag = user(1)
    del noflag["accountEnabled"]
    unevaluated(t(body([assignment(1)], [noflag])), "accountEnabled")


@pytest.mark.parametrize("copy,mode", CASES)
def test_seven_digit_fraction_parses(copy, mode):
    u = user(1)
    u["signInActivity"]["lastSuccessfulSignInDateTime"] = iso(100)[:-1] + ".1234567Z"
    assert out_of(load(copy, mode)(body([assignment(1)], [u]))) == 1
