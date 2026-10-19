"""Microsoft Entra ID popImapSignInAccountCount: accounts that signed in successfully with POP or IMAP in 30 days.

Input is the getPopImapSignInEvidence workflow output {"signIns": <Graph body>, "paginationStats": {"signIns":
{"paginationTruncated": bool}}}, as the Azure AD app registration and One-Click definitions produce it (tracker
row 61). Every case runs as plain Python and in the Token-Service sandbox replica. Synthetic data only (x.test,
zero-filled ids).
"""
import importlib.util
import json
import pathlib

import pytest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PATH = HERE / "popimapsigninaccountcount.py"
TAG = "entra_pop_imap"
KEY = "popImapSignInAccountCount"

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
    spec = importlib.util.spec_from_file_location(TAG, PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def oid(n):
    return "00000000-0000-0000-0000-%012d" % n


def sign_in(n, app="IMAP4", code=0, upn="auto", display="auto", uid="auto"):
    return {
        "id": "sign-in-%d-%s" % (n, app),
        "createdDateTime": "2026-10-01T12:00:00Z",
        "userId": oid(n) if uid == "auto" else uid,
        "userPrincipalName": ("user%03d@x.test" % n) if upn == "auto" else upn,
        "userDisplayName": ("User %03d" % n) if display == "auto" else display,
        "clientAppUsed": app,
        "status": {"errorCode": code, "failureReason": None if code == 0 else "Other.", "additionalDetails": None},
    }


def body(entries, truncated=False, stats=True, next_link=None):
    graph = {"@odata.context": "https://graph.microsoft.com/v1.0/$metadata#auditLogs/signIns", "value": entries}
    if next_link:
        graph["@odata.nextLink"] = next_link
    out = {"signIns": graph}
    if stats:
        out["paginationStats"] = {"signIns": {"paginationTruncated": truncated}}
    if truncated:
        out["paginationTruncated"] = True
    return out


def out_of(out):
    return out["transformedResponse"][KEY]


def info(out):
    return out["additionalInfo"]


def unevaluated(out, needle):
    assert out_of(out) is None
    assert info(out)["dataCollection"]["status"] == "error"
    assert info(out)["evaluation"]["passReasons"] == []
    text = " ".join(info(out)["dataCollection"]["errors"])
    assert needle in text, text


@pytest.mark.parametrize("mode", MODES)
def test_no_pop_imap_sign_in_from_a_complete_read_is_zero(mode):
    out = load(mode)(body([]))
    assert out_of(out) == 0
    assert info(out)["dataCollection"]["status"] == "success"
    passes = info(out)["evaluation"]["passReasons"]
    assert passes[0] == "Microsoft Entra ID sign-in log: no account signed in with POP or IMAP in the last 30 days"
    assert passes[1].startswith("Not covered: only interactive sign-ins are read")
    assert info(out)["evaluation"]["failReasons"] == []


@pytest.mark.parametrize("mode", MODES)
def test_accounts_are_named_with_their_protocols(mode):
    entries = [sign_in(2, "POP3"), sign_in(1, "IMAP4"), sign_in(1, "POP3"), sign_in(1, "IMAP4")]
    out = load(mode)(body(entries))
    assert out_of(out) == 2
    fails = info(out)["evaluation"]["failReasons"]
    assert fails[0] == ("Microsoft Entra ID sign-in log: 2 account(s) signed in successfully with POP or IMAP in the "
                        "last 30 days: user001@x.test (IMAP4, POP3), user002@x.test (POP3)")
    assert fails[-1].startswith("Not covered:")
    summary = info(out)["transformation"]["inputSummary"]
    assert summary["affectedAccounts"] == ["user001@x.test (IMAP4, POP3)", "user002@x.test (POP3)"]
    assert summary["affectedAccountCount"] == 2
    assert summary["popImapSignInsRead"] == 4
    assert summary["readComplete"] is True
    assert "Set-CASMailbox" in info(out)["evaluation"]["recommendations"][0]


@pytest.mark.parametrize("mode", MODES)
def test_names_capped_at_twenty_five_and_n_more(mode):
    out = load(mode)(body([sign_in(n) for n in range(1, 31)]))
    assert out_of(out) == 30
    first = info(out)["evaluation"]["failReasons"][0]
    assert first.count("@x.test") == 25
    assert first.endswith("user025@x.test (IMAP4) and 5 more")
    assert len(info(out)["transformation"]["inputSummary"]["affectedAccounts"]) == 30


@pytest.mark.parametrize("mode", MODES)
def test_exactly_twenty_five_has_no_more_suffix(mode):
    first = info(load(mode)(body([sign_in(n) for n in range(1, 26)])))["evaluation"]["failReasons"][0]
    assert first.count("@x.test") == 25
    assert "more" not in first


@pytest.mark.parametrize("mode", MODES)
def test_affected_accounts_summary_capped_at_fifty(mode):
    out = load(mode)(body([sign_in(n) for n in range(1, 61)]))
    summary = info(out)["transformation"]["inputSummary"]
    assert out_of(out) == 60
    assert len(summary["affectedAccounts"]) == 50
    assert summary["affectedAccountCount"] == 60


@pytest.mark.parametrize("mode", MODES)
def test_display_name_then_user_id_when_no_upn(mode):
    entries = [sign_in(1, upn=""), sign_in(2, upn=None, display=None)]
    first = info(load(mode)(body(entries)))["evaluation"]["failReasons"][0]
    assert "User 001 (IMAP4)" in first
    assert oid(2) + " (IMAP4)" in first


@pytest.mark.parametrize("mode", MODES)
def test_doc_spellings_pop_and_imap_are_accepted(mode):
    out = load(mode)(body([sign_in(1, "pop"), sign_in(2, "Imap")]))
    assert out_of(out) == 2
    assert "user001@x.test (POP3), user002@x.test (IMAP4)" in info(out)["evaluation"]["failReasons"][0]


@pytest.mark.parametrize("mode", MODES)
def test_other_clients_are_ignored(mode):
    out = load(mode)(body([sign_in(1, "Browser"), sign_in(2, "Exchange ActiveSync"), sign_in(3, "Authenticated SMTP")]))
    assert out_of(out) == 0
    assert info(out)["transformation"]["inputSummary"]["otherSignInsIgnored"] == 3


@pytest.mark.parametrize("mode", MODES)
def test_failed_attempts_are_not_counted_but_are_named(mode):
    entries = [sign_in(1, "IMAP4", code=50126), sign_in(2, "POP3", code=53003), sign_in(3, "IMAP4")]
    out = load(mode)(body(entries))
    assert out_of(out) == 1
    assert info(out)["evaluation"]["failReasons"][0].endswith("in the last 30 days: user003@x.test (IMAP4)")
    finding = info(out)["evaluation"]["additionalFindings"][0]
    assert finding == ("Microsoft Entra ID: 2 account(s) had POP or IMAP sign-in attempts in the last 30 days that all "
                       "failed (blocked or wrong credentials), so the protocol is still being tried against them: "
                       "user001@x.test (IMAP4), user002@x.test (POP3)")


@pytest.mark.parametrize("mode", MODES)
def test_only_failed_attempts_is_zero_with_the_attempts_named(mode):
    out = load(mode)(body([sign_in(1, "IMAP4", code=50126)]))
    assert out_of(out) == 0
    assert info(out)["evaluation"]["passReasons"][0] == (
        "Microsoft Entra ID sign-in log: no account signed in successfully with POP or IMAP in the last 30 days "
        "(1 POP or IMAP sign-in(s) read, all failed)")
    assert "user001@x.test (IMAP4)" in info(out)["evaluation"]["additionalFindings"][0]


@pytest.mark.parametrize("mode", MODES)
def test_an_account_with_one_success_is_not_also_listed_as_failed(mode):
    out = load(mode)(body([sign_in(1, code=50126), sign_in(1, code=0)]))
    assert out_of(out) == 1
    assert info(out)["evaluation"]["additionalFindings"] == []


@pytest.mark.parametrize("mode", MODES)
def test_truncated_read_with_accounts_found_fails_as_at_least(mode):
    out = load(mode)(body([sign_in(1)], truncated=True))
    assert out_of(out) == 1
    fails = info(out)["evaluation"]["failReasons"]
    assert fails[0].startswith("Microsoft Entra ID sign-in log: at least 1 account(s) signed in successfully")
    assert "more accounts may have used POP or IMAP" in fails[1]
    assert info(out)["transformation"]["inputSummary"]["readComplete"] is False


@pytest.mark.parametrize("mode", MODES)
def test_truncated_read_with_none_found_is_not_evaluated(mode):
    unevaluated(load(mode)(body([], truncated=True)), "not read to the end")


@pytest.mark.parametrize("mode", MODES)
def test_next_link_left_with_none_found_is_not_evaluated(mode):
    unevaluated(load(mode)(body([], next_link="https://graph.microsoft.com/v1.0/auditLogs/signIns?$skiptoken=x")),
                "@odata.nextLink remains")


@pytest.mark.parametrize("mode", MODES)
def test_no_completeness_marker_with_none_found_is_not_evaluated(mode):
    unevaluated(load(mode)(body([], stats=False)), "cannot be shown complete")


@pytest.mark.parametrize("mode", MODES)
def test_no_completeness_marker_with_accounts_found_still_fails(mode):
    out = load(mode)(body([sign_in(1)], stats=False))
    assert out_of(out) == 1
    assert "at least 1 account(s)" in info(out)["evaluation"]["failReasons"][0]


@pytest.mark.parametrize("mode", MODES)
def test_missing_permission_refusal_is_not_evaluated(mode):
    marker = {"vendorErrorAsResponse": {
        "status": 403, "bodyContains": "Authorization_RequestDenied", "kind": "missing_permission",
        "requiredScopes": ["AuditLog.Read.All"],
        "body": {"error": {"code": "Authorization_RequestDenied", "message": "Insufficient privileges."}}}}
    unevaluated(load(mode)(marker), "AuditLog.Read.All")
    unevaluated(load(mode)({"signIns": marker}), "AuditLog.Read.All")


@pytest.mark.parametrize("mode", MODES)
def test_no_premium_licence_is_not_evaluated(mode):
    marker = {"vendorErrorAsResponse": {
        "status": 403, "bodyContains": "Authentication_RequestFromNonPremiumTenantOrB2CTenant", "kind": "not_licensed",
        "body": {"error": {"code": "Authentication_RequestFromNonPremiumTenantOrB2CTenant",
                           "message": "Neither tenant is B2C or tenant doesn't have premium license"}}}}
    unevaluated(load(mode)(marker), "needs Entra ID P1")


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("status", [400, 429, 500])
def test_other_refusals_are_not_evaluated(mode, status):
    marker = {"vendorErrorAsResponse": {"status": status, "bodyContains": "error", "body": {"error": "x"}}}
    unevaluated(load(mode)(marker), "Microsoft Graph")


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("payload,needle", [
    ({}, "is missing"),
    ({"signIns": None}, "not an object"),
    ({"signIns": {"error": {"code": "UnknownError", "message": "boom"}}}, "UnknownError"),
    ({"signIns": {"statusCode": 503}}, "HTTP 503"),
    ({"signIns": {"value": "not a list"}}, "no value list"),
    ({"signIns": {"value": ["not an object"]}, "paginationStats": {"signIns": {"paginationTruncated": False}}},
     "not an object"),
    (None, "not an object"),
    ("", "not an object"),
    ([], "not an object"),
])
def test_unreadable_bodies_are_not_evaluated(mode, payload, needle):
    unevaluated(load(mode)(payload), needle)


@pytest.mark.parametrize("mode", MODES)
def test_unreadable_status_is_not_evaluated_never_a_pass_or_fail(mode):
    entry = sign_in(1)
    entry["status"] = {"errorCode": None}
    unevaluated(load(mode)(body([entry])), "no readable status.errorCode")
    entry["status"] = "ok"
    unevaluated(load(mode)(body([sign_in(2), entry])), "no readable status.errorCode")


@pytest.mark.parametrize("mode", MODES)
def test_pagination_error_stub_is_not_evaluated(mode):
    stub = {"error": True, "errorType": "pagination_incomplete", "status": "Error", "statusCode": 429,
            "message": "Pagination stopped at page 3"}
    unevaluated(load(mode)({"signIns": stub}), "Microsoft Graph returned an error")


@pytest.mark.parametrize("mode", MODES)
def test_string_and_bytes_input(mode):
    raw = json.dumps(body([sign_in(1)]))
    assert out_of(load(mode)(raw)) == 1
    assert out_of(load(mode)(raw.encode("utf-8"))) == 1


@pytest.mark.parametrize("mode", MODES)
def test_wrapped_and_direct_shapes(mode):
    assert out_of(load(mode)({"apiResponse": body([sign_in(1)])})) == 1
    # A direct method call (no workflow) carries no paginationStats: a finding still names accounts, 0 cannot pass.
    direct = {"value": [sign_in(1)]}
    assert out_of(load(mode)(direct)) == 1
    unevaluated(load(mode)({"value": []}), "cannot be shown complete")


@pytest.mark.parametrize("mode", MODES)
def test_overlong_name_is_clipped(mode):
    out = load(mode)(body([sign_in(1, upn="u" * 300 + "@x.test")]))
    first = info(out)["evaluation"]["failReasons"][0]
    assert "u" * 100 in first and "u" * 101 not in first
