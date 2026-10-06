"""Tests for JumpCloud areAdminAccountsSeparate.

Fixtures (fixtures/areAdminAccountsSeparate_{pass,fail}.json) follow the JumpCloud list shapes the
definition already reads: GET /api/users (administrators: results + totalCount, roleName, suspended)
and GET /api/systemusers (directory users: results + totalCount, email, state, suspended), merged under
the workflow output keys administrators and systemUsers. Every case runs as plain Python and compiled
the way Token-Service runs it (tools/restricted_sandbox.py).
"""
import importlib.util
import json
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PATH = HERE / "areAdminAccountsSeparate.py"
KEY = "areAdminAccountsSeparate"


def native():
    spec = importlib.util.spec_from_file_location("jc_areadminaccountsseparate", PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def sandboxed():
    spec = importlib.util.spec_from_file_location("restricted_sandbox_jc_admin_sep", ROOT / "tools" / "restricted_sandbox.py")
    sandbox = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sandbox)
    return sandbox.load(PATH.read_text(), "<transformation>")["transform"]


RUNNERS = [pytest.param(native, id="native"), pytest.param(sandboxed, id="sandbox")]


def fixture(name):
    return json.loads((HERE / "fixtures" / ("areAdminAccountsSeparate_" + name + ".json")).read_text())


def not_evaluated(out):
    return out["transformedResponse"][KEY] is None and out["additionalInfo"]["dataCollection"]["status"] == "error"


@pytest.mark.parametrize("loader", RUNNERS)
def test_passing_fixture_passes(loader):
    out = loader()(fixture("pass"))
    assert out["transformedResponse"][KEY] is True
    assert out["transformedResponse"]["adminCount"] == 2


@pytest.mark.parametrize("loader", RUNNERS)
def test_failing_fixture_fails_and_names_the_record_not_the_email(loader):
    out = loader()(fixture("fail"))
    assert out["transformedResponse"][KEY] is False
    reason = out["additionalInfo"]["evaluation"]["failReasons"][0]
    assert "6501a0000000000000000003" in reason
    assert "kim@example.com" not in json.dumps(out)


@pytest.mark.parametrize("loader", RUNNERS)
@pytest.mark.parametrize("body", [None, {}, "{}", "", {"hello": "world"}, {"foo": {"bar": [1, 2, 3]}},
                                  {"statusCode": 401, "error": "Unauthorized"}, {"statusCode": 403, "error": "Forbidden"},
                                  {"error": {"statusCode": 401, "message": "Unauthorized"}},
                                  {"results": [], "totalCount": 0}])
def test_no_evidence_is_not_evaluated(loader, body):
    assert not_evaluated(loader()(body))


@pytest.mark.parametrize("loader", RUNNERS)
def test_partial_admin_list_is_not_evaluated(loader):
    body = fixture("pass")
    body["administrators"]["totalCount"] = 5
    assert not_evaluated(loader()(body))


@pytest.mark.parametrize("loader", RUNNERS)
def test_partial_user_list_is_not_evaluated(loader):
    body = fixture("pass")
    body["systemUsers"]["totalCount"] = 250
    assert not_evaluated(loader()(body))


@pytest.mark.parametrize("loader", RUNNERS)
def test_partial_read_with_a_proven_match_still_fails(loader):
    body = fixture("fail")
    body["systemUsers"]["totalCount"] = 250
    assert loader()(body)["transformedResponse"][KEY] is False


@pytest.mark.parametrize("loader", RUNNERS)
def test_missing_user_list_is_not_evaluated(loader):
    body = fixture("pass")
    body.pop("systemUsers")
    assert not_evaluated(loader()(body))


@pytest.mark.parametrize("loader", RUNNERS)
def test_failed_user_read_is_not_evaluated(loader):
    body = fixture("pass")
    body["systemUsers"] = {"statusCode": 403, "error": "Forbidden"}
    assert not_evaluated(loader()(body))


@pytest.mark.parametrize("loader", RUNNERS)
def test_match_is_case_insensitive(loader):
    body = fixture("fail")
    body["administrators"]["results"][1]["email"] = " KIM@Example.com "
    assert loader()(body)["transformedResponse"][KEY] is False


@pytest.mark.parametrize("loader", RUNNERS)
def test_suspended_admin_is_not_judged(loader):
    body = fixture("fail")
    body["administrators"]["results"][1]["suspended"] = True
    assert loader()(body)["transformedResponse"][KEY] is True


@pytest.mark.parametrize("loader", RUNNERS)
def test_staged_directory_user_counts_as_everyday(loader):
    body = fixture("fail")
    body["systemUsers"]["results"][1]["state"] = "STAGED"
    body["systemUsers"]["results"][1]["activated"] = False
    assert loader()(body)["transformedResponse"][KEY] is False


@pytest.mark.parametrize("loader", RUNNERS)
def test_admin_without_email_is_not_evaluated(loader):
    body = fixture("pass")
    body["administrators"]["results"][0].pop("email")
    assert not_evaluated(loader()(body))


@pytest.mark.parametrize("loader", RUNNERS)
def test_all_admins_suspended_is_not_evaluated(loader):
    body = fixture("pass")
    for admin in body["administrators"]["results"]:
        admin["suspended"] = True
    assert not_evaluated(loader()(body))


@pytest.mark.parametrize("loader", RUNNERS)
def test_workflow_pagination_marker_is_not_evaluated(loader):
    body = fixture("pass")
    body["paginationStats"] = {"systemUsers": {"paginationTruncated": True}}
    assert not_evaluated(loader()(body))
    body = fixture("pass")
    body["paginationTruncated"] = True
    assert not_evaluated(loader()(body))
