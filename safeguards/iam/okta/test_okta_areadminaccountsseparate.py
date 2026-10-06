"""Tests for iam/okta/areAdminAccountsSeparate.py.

Fixtures (fixtures/okta_admin_app_assignments_{pass,fail}.json) follow the Okta Management API spec
examples: RoleAssignedUsersResponseExample for GET /api/v1/iam/assignees/users and ListAppLinks for
GET /api/v1/users/{id}/appLinks, merged by the getAdminAppAssignments workflow under adminAssignees and
adminAppLinks (index-aligned), with the paginationStats / iterateStats markers Integration-Service adds.
Every case runs as plain Python and compiled the way Token-Service runs it (tools/restricted_sandbox.py).
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
    spec = importlib.util.spec_from_file_location("okta_areadminaccountsseparate", PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def sandboxed():
    spec = importlib.util.spec_from_file_location("restricted_sandbox_okta_admin_sep", ROOT / "tools" / "restricted_sandbox.py")
    sandbox = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sandbox)
    return sandbox.load(PATH.read_text(), "<transformation>")["transform"]


RUNNERS = [pytest.param(native, id="native"), pytest.param(sandboxed, id="sandbox")]


def fixture(name):
    return json.loads((HERE / "fixtures" / ("okta_admin_app_assignments_" + name + ".json")).read_text())


def verdict(out):
    return out["transformedResponse"][KEY]


def not_evaluated(out):
    return verdict(out) is None and out["additionalInfo"]["dataCollection"]["status"] == "error"


@pytest.mark.parametrize("loader", RUNNERS)
def test_passing_fixture_passes(loader):
    out = loader()(fixture("pass"))
    assert verdict(out) is True
    assert out["transformedResponse"]["adminCount"] == 2


@pytest.mark.parametrize("loader", RUNNERS)
def test_failing_fixture_fails_and_names_the_admin(loader):
    out = loader()(fixture("fail"))
    assert verdict(out) is False
    reason = out["additionalInfo"]["evaluation"]["failReasons"][0]
    assert "00u1usr0000000000003" in reason and "google" in reason and "office365" in reason


@pytest.mark.parametrize("loader", RUNNERS)
@pytest.mark.parametrize("body", [None, {}, "{}", "", {"hello": "world"}, {"foo": {"bar": [1, 2, 3]}},
                                  {"statusCode": 401, "error": "Unauthorized"},
                                  {"errorCode": "E0000006", "errorSummary": "You do not have permission"},
                                  # the old input: a plain user roster is not evidence
                                  [{"id": "00u1", "status": "ACTIVE", "profile": {"login": "admin@example.com"}}]])
def test_no_evidence_is_not_evaluated(loader, body):
    assert not_evaluated(loader()(body))


@pytest.mark.parametrize("loader", RUNNERS)
def test_roles_scope_missing_is_not_evaluated(loader):
    body = fixture("pass")
    body["adminAssignees"] = {"vendorErrorAsResponse": {"status": 403}, "errorCode": "E0000006"}
    out = loader()(body)
    assert not_evaluated(out)
    assert "okta.roles.read" in out["additionalInfo"]["dataCollection"]["errors"][0]


@pytest.mark.parametrize("loader", RUNNERS)
def test_empty_admin_list_is_not_evaluated(loader):
    body = fixture("pass")
    body["adminAssignees"]["value"] = []
    body["adminAppLinks"] = []
    assert not_evaluated(loader()(body))


@pytest.mark.parametrize("loader", RUNNERS)
def test_truncated_admin_list_is_not_evaluated(loader):
    body = fixture("pass")
    body["paginationStats"]["adminAssignees"]["paginationTruncated"] = True
    assert not_evaluated(loader()(body))


@pytest.mark.parametrize("loader", RUNNERS)
def test_unreported_pagination_is_not_evaluated(loader):
    body = fixture("pass")
    body.pop("paginationStats")
    assert not_evaluated(loader()(body))


@pytest.mark.parametrize("loader", RUNNERS)
def test_capped_reads_with_a_productivity_admin_still_fail(loader):
    body = fixture("fail")
    body["iterateStats"]["adminAppLinks"]["iterateTruncated"] = True
    assert verdict(loader()(body)) is False


@pytest.mark.parametrize("loader", RUNNERS)
def test_failed_item_read_is_not_evaluated(loader):
    body = fixture("pass")
    body["adminAppLinks"][1] = {"error": True, "statusCode": 429, "item": "00u1adm0000000000002",
                                "errorType": "rate_limited"}
    assert not_evaluated(loader()(body))


@pytest.mark.parametrize("loader", RUNNERS)
def test_misaligned_slots_give_no_verdict_even_with_a_productivity_app(loader):
    body = fixture("fail")
    body["adminAppLinks"].reverse()
    assert not_evaluated(loader()(body))
    body = fixture("fail")
    body["adminAppLinks"].append([])
    assert not_evaluated(loader()(body))


@pytest.mark.parametrize("loader", RUNNERS)
def test_missing_slots_without_cap_are_not_evaluated(loader):
    body = fixture("pass")
    body["adminAppLinks"] = body["adminAppLinks"][:1]
    assert not_evaluated(loader()(body))


@pytest.mark.parametrize("loader", RUNNERS)
def test_admin_with_no_apps_is_dedicated(loader):
    body = fixture("fail")
    body["adminAppLinks"][1] = []
    assert verdict(loader()(body)) is True
