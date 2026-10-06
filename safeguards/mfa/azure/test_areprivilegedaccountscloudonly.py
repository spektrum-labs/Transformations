"""Tests for arePrivilegedAccountsCloudOnly (Microsoft Entra ID), in mfa/azure and 874a78ff-.../.

Fixtures (fixtures/areprivilegedaccountscloudonly_{pass,fail}.json) follow the Microsoft Graph v1.0
list shapes for GET /roleManagement/directory/roleAssignments?$expand=principal($select=id) and
GET /users?$select=id,userPrincipalName,accountEnabled,onPremisesSyncEnabled,onPremisesImmutableId,
merged under the workflow output keys roleAssignments and users. Every case runs twice: imported as
plain Python, and compiled the way Token-Service runs it (tools/restricted_sandbox.py).
"""
import copy
import importlib.util
import json
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
KEY = "arePrivilegedAccountsCloudOnly"
GA = "62e90394-69f5-4237-9190-012177145e10"
FILES = [ROOT / "safeguards" / "mfa" / "azure" / "areprivilegedaccountscloudonly.py",
         ROOT / "safeguards" / "874a78ff-2ca3-4c0e-ab86-19277536ac87" / "areprivilegedaccountscloudonly.py"]


def native(path):
    spec = importlib.util.spec_from_file_location("cloudonly_" + path.parent.name.replace("-", "_"), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def sandboxed(path):
    spec = importlib.util.spec_from_file_location("restricted_sandbox_cloudonly", ROOT / "tools" / "restricted_sandbox.py")
    sandbox = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sandbox)
    return sandbox.load(path.read_text(), "<transformation>")["transform"]


RUNNERS = []
for f in FILES:
    RUNNERS.append(pytest.param(f, native, id=f.parent.name[:8] + "-native"))
    RUNNERS.append(pytest.param(f, sandboxed, id=f.parent.name[:8] + "-sandbox"))


def fixture(path, name):
    return json.loads((path.parent / "fixtures" / ("areprivilegedaccountscloudonly_" + name + ".json")).read_text())


def run(path, loader, body):
    return loader(path)(body)


def verdict(out):
    return out["transformedResponse"][KEY]


def not_evaluated(out):
    return verdict(out) is None and out["additionalInfo"]["dataCollection"]["status"] == "error"


def test_the_two_copies_are_identical():
    assert FILES[0].read_text() == FILES[1].read_text()


@pytest.mark.parametrize("path,loader", RUNNERS)
def test_passing_fixture_passes(path, loader):
    out = run(path, loader, fixture(path, "pass"))
    assert verdict(out) is True
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"
    assert out["transformedResponse"]["privilegedUserCount"] == 2


@pytest.mark.parametrize("path,loader", RUNNERS)
def test_failing_fixture_fails_and_names_the_synced_admin(path, loader):
    out = run(path, loader, fixture(path, "fail"))
    assert verdict(out) is False
    assert out["transformedResponse"]["syncedPrivilegedAccounts"] == 1
    assert "alex@contoso.com" in out["additionalInfo"]["evaluation"]["failReasons"][0]


@pytest.mark.parametrize("path,loader", RUNNERS)
@pytest.mark.parametrize("body", [None, {}, "{}", "", {"hello": "world"}, {"foo": {"bar": [1, 2, 3]}},
                                  {"error": {"code": "Authorization_RequestDenied", "message": "Insufficient privileges"}},
                                  {"statusCode": 401, "error": "Unauthorized"}, {"statusCode": 403, "error": "Forbidden"},
                                  {"PSError": "boom"}])
def test_no_evidence_is_not_evaluated(path, loader, body):
    assert not_evaluated(run(path, loader, body))


@pytest.mark.parametrize("path,loader", RUNNERS)
def test_truncated_read_is_not_evaluated(path, loader):
    body = fixture(path, "pass")
    body["users"]["@odata.nextLink"] = "https://graph.microsoft.com/v1.0/users?$skiptoken=abc"
    assert not_evaluated(run(path, loader, body))


@pytest.mark.parametrize("path,loader", RUNNERS)
def test_truncated_read_with_a_synced_admin_is_still_a_measured_fail(path, loader):
    body = fixture(path, "fail")
    body["users"]["@odata.nextLink"] = "https://graph.microsoft.com/v1.0/users?$skiptoken=abc"
    assert verdict(run(path, loader, body)) is False


@pytest.mark.parametrize("path,loader", RUNNERS)
def test_user_read_without_sync_field_is_not_evaluated(path, loader):
    """getUsersWithLicenses does not $select onPremisesSyncEnabled: absence is not cloud-only."""
    body = fixture(path, "pass")
    for user in body["users"]["value"]:
        user.pop("onPremisesSyncEnabled")
    out = run(path, loader, body)
    assert not_evaluated(out)
    assert "onPremisesSyncEnabled" in out["additionalInfo"]["dataCollection"]["errors"][0]


@pytest.mark.parametrize("path,loader", RUNNERS)
def test_stringified_true_is_synced(path, loader):
    body = fixture(path, "fail")
    for user in body["users"]["value"]:
        if user["onPremisesSyncEnabled"] is True:
            user["onPremisesSyncEnabled"] = "True"
    assert verdict(run(path, loader, body)) is False


@pytest.mark.parametrize("path,loader", RUNNERS)
def test_formerly_synced_admin_passes_with_a_finding(path, loader):
    body = fixture(path, "pass")
    body["users"]["value"][0]["onPremisesSyncEnabled"] = False
    body["users"]["value"][0]["onPremisesImmutableId"] = "AAAAAAAAAAAAAAAAAAAAAA=="
    out = run(path, loader, body)
    assert verdict(out) is True
    findings = " ".join(out["additionalInfo"]["evaluation"]["additionalFindings"])
    assert "now cloud-managed" in findings and "immutable id" in findings


@pytest.mark.parametrize("path,loader", RUNNERS)
def test_disabled_synced_admin_is_not_judged(path, loader):
    body = fixture(path, "fail")
    for user in body["users"]["value"]:
        if user["onPremisesSyncEnabled"] is True:
            user["accountEnabled"] = False
    assert verdict(run(path, loader, body)) is True


@pytest.mark.parametrize("path,loader", RUNNERS)
def test_group_role_holder_is_not_evaluated(path, loader):
    body = fixture(path, "pass")
    body["roleAssignments"]["value"].append({
        "id": "grp", "principalId": "9b9b9b9b-0000-4000-8000-000000000009", "roleDefinitionId": GA,
        "directoryScopeId": "/", "principal": {"@odata.type": "#microsoft.graph.group",
                                                "id": "9b9b9b9b-0000-4000-8000-000000000009"}})
    assert not_evaluated(run(path, loader, body))


@pytest.mark.parametrize("path,loader", RUNNERS)
def test_no_privileged_user_is_not_evaluated(path, loader):
    body = fixture(path, "pass")
    body["roleAssignments"]["value"] = []
    assert not_evaluated(run(path, loader, body))


@pytest.mark.parametrize("path,loader", RUNNERS)
def test_engine_wrappers_are_peeled(path, loader):
    body = {"apiResponse": copy.deepcopy(fixture(path, "pass"))}
    assert verdict(run(path, loader, body)) is True
    wrapped = fixture(path, "fail")
    wrapped["users"] = {"rawResponse": wrapped["users"]}
    assert verdict(run(path, loader, wrapped)) is False


@pytest.mark.parametrize("path,loader", RUNNERS)
def test_one_failed_read_is_not_evaluated(path, loader):
    body = fixture(path, "pass")
    body["users"] = {"error": {"code": "Authorization_RequestDenied", "message": "Insufficient privileges"}}
    out = run(path, loader, body)
    assert not_evaluated(out)
    assert "403" in out["additionalInfo"]["dataCollection"]["errors"][0]


@pytest.mark.parametrize("path,loader", RUNNERS)
def test_workflow_pagination_marker_is_not_evaluated(path, loader):
    body = fixture(path, "pass")
    body["paginationStats"] = {"users": {"paginationTruncated": True}}
    assert not_evaluated(run(path, loader, body))


# --- Review fix (#1006 / #1007): an untyped principal missing from the user read is named as such ---

@pytest.mark.parametrize("path,loader", RUNNERS)
@pytest.mark.parametrize("principal", [None, {"id": "7c7c7c7c-0000-4000-8000-00000000007c"}])
def test_untyped_principal_not_in_user_read_says_why(path, loader, principal):
    body = fixture(path, "pass")
    row = {"id": "sp", "principalId": "7c7c7c7c-0000-4000-8000-00000000007c", "roleDefinitionId": GA,
           "directoryScopeId": "/"}
    if principal is not None:
        row["principal"] = principal
    body["roleAssignments"]["value"].append(row)
    out = run(path, loader, body)
    assert not_evaluated(out)
    errors = " ".join(out["additionalInfo"]["dataCollection"]["errors"])
    assert "no @odata.type" in errors and "service principal" in errors
    assert out["additionalInfo"]["transformation"]["inputSummary"]["untypedPrincipalsNotInUserRead"] == 1
    assert any("principal type" in r for r in out["additionalInfo"]["evaluation"]["recommendations"])


@pytest.mark.parametrize("path,loader", RUNNERS)
def test_typed_user_not_in_user_read_is_not_called_a_service_principal(path, loader):
    body = fixture(path, "pass")
    body["roleAssignments"]["value"].append({
        "id": "u", "principalId": "7c7c7c7c-0000-4000-8000-00000000007d", "roleDefinitionId": GA,
        "directoryScopeId": "/", "principal": {"@odata.type": "#microsoft.graph.user",
                                                "id": "7c7c7c7c-0000-4000-8000-00000000007d"}})
    out = run(path, loader, body)
    assert not_evaluated(out)
    errors = " ".join(out["additionalInfo"]["dataCollection"]["errors"])
    assert "a user not in the user read" in errors and "service principal" not in errors
