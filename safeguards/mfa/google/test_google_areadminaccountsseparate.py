"""Tests for mfa/google/areadminaccountsseparate.py (Google Workspace areAdminAccountsSeparate).

Fixtures (fixtures/areadminaccountsseparate_{pass,fail}.json) follow the Directory API users.list
response ({"kind": "admin#directory#users", "users": [User...], "nextPageToken"?}) with the documented
User fields isAdmin, isDelegatedAdmin, isMailboxSetup, suspended and archived. Every case runs as plain
Python and compiled the way Token-Service runs it (tools/restricted_sandbox.py).
"""
import importlib.util
import json
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PATH = HERE / "areadminaccountsseparate.py"
KEY = "areAdminAccountsSeparate"


def native():
    spec = importlib.util.spec_from_file_location("google_areadminaccountsseparate", PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def sandboxed():
    spec = importlib.util.spec_from_file_location("restricted_sandbox_google_admin_sep", ROOT / "tools" / "restricted_sandbox.py")
    sandbox = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sandbox)
    return sandbox.load(PATH.read_text(), "<transformation>")["transform"]


RUNNERS = [pytest.param(native, id="native"), pytest.param(sandboxed, id="sandbox")]


def fixture(name):
    return json.loads((HERE / "fixtures" / ("areadminaccountsseparate_" + name + ".json")).read_text())


def not_evaluated(out):
    return out["transformedResponse"][KEY] is None and out["additionalInfo"]["dataCollection"]["status"] == "error"


@pytest.mark.parametrize("loader", RUNNERS)
def test_passing_fixture_passes(loader):
    out = loader()(fixture("pass"))
    assert out["transformedResponse"][KEY] is True
    assert out["transformedResponse"]["adminCount"] == 2


@pytest.mark.parametrize("loader", RUNNERS)
def test_failing_fixture_fails_and_names_the_admin_with_a_mailbox(loader):
    out = loader()(fixture("fail"))
    assert out["transformedResponse"][KEY] is False
    assert "pat@example.com" in out["additionalInfo"]["evaluation"]["failReasons"][0]


@pytest.mark.parametrize("loader", RUNNERS)
@pytest.mark.parametrize("body", [None, {}, "{}", "", {"hello": "world"}, {"foo": {"bar": [1, 2, 3]}}, {"users": []},
                                  {"error": {"code": 403, "message": "Not Authorized to access this resource/api",
                                             "status": "PERMISSION_DENIED"}},
                                  {"statusCode": 401, "error": "Unauthorized"},
                                  {"error": "unauthorized_client", "error_description": "Client is unauthorized"}])
def test_no_evidence_is_not_evaluated(loader, body):
    assert not_evaluated(loader()(body))


@pytest.mark.parametrize("loader", RUNNERS)
def test_next_page_token_is_not_evaluated(loader):
    body = fixture("pass")
    body["nextPageToken"] = "Q0FFU0FBPT0"
    assert not_evaluated(loader()(body))


@pytest.mark.parametrize("loader", RUNNERS)
def test_truncated_list_with_a_mailbox_admin_still_fails(loader):
    body = fixture("fail")
    body["nextPageToken"] = "Q0FFU0FBPT0"
    assert loader()(body)["transformedResponse"][KEY] is False


@pytest.mark.parametrize("loader", RUNNERS)
def test_stringified_booleans_are_read(loader):
    body = fixture("fail")
    for user in body["users"]:
        for k in ("isAdmin", "isDelegatedAdmin", "isMailboxSetup", "suspended", "archived"):
            user[k] = "True" if user[k] else "False"
    assert loader()(body)["transformedResponse"][KEY] is False
    body = fixture("pass")
    for user in body["users"]:
        for k in ("isAdmin", "isDelegatedAdmin", "isMailboxSetup", "suspended", "archived"):
            user[k] = "True" if user[k] else "False"
    assert loader()(body)["transformedResponse"][KEY] is True


@pytest.mark.parametrize("loader", RUNNERS)
def test_admin_without_mailbox_field_is_not_evaluated(loader):
    body = fixture("pass")
    body["users"][0].pop("isMailboxSetup")
    assert not_evaluated(loader()(body))


@pytest.mark.parametrize("loader", RUNNERS)
def test_no_active_admin_is_not_evaluated(loader):
    body = fixture("pass")
    body["users"] = [u for u in body["users"] if not (u["isAdmin"] or u["isDelegatedAdmin"])]
    assert not_evaluated(loader()(body))


@pytest.mark.parametrize("loader", RUNNERS)
def test_wrapped_and_workflow_merged_bodies(loader):
    assert loader()({"apiResponse": fixture("pass")})["transformedResponse"][KEY] is True
    assert loader()({"users": fixture("fail")})["transformedResponse"][KEY] is False
    assert loader()({"rawResponse": fixture("fail")["users"]})["transformedResponse"][KEY] is False


@pytest.mark.parametrize("loader", RUNNERS)
def test_workflow_pagination_marker_is_not_evaluated(loader):
    body = {"users": fixture("pass"), "paginationStats": {"users": {"paginationTruncated": True}}}
    assert not_evaluated(loader()(body))
