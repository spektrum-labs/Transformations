"""Tests for iam/okta/areAdminAccountsSeparate.py.

Fixtures (fixtures/okta_admin_app_assignments_{pass,fail}.json) follow the Okta Management API spec
examples: RoleAssignedUsersResponseExample for GET /api/v1/iam/assignees/users and ListAppLinks for
GET /api/v1/users/{id}/appLinks, merged by the getAdminAppAssignments workflow under adminAssignees and
adminAppLinks (index-aligned), with the paginationStats / iterateStats markers Integration-Service adds.
The passing fixture also carries the optional orgApps read (an ACTIVE Office 365 app), the evidence a
pass needs that the org's mailbox is assigned through Okta at all.
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
    assert not_evaluated(loader()(body))  # no evidence the org's mailbox is assigned through Okta
    body["orgApps"] = fixture("pass")["orgApps"]
    assert verdict(loader()(body)) is True


# --- Review fixes (#1006 / #1007): a pass needs evidence that could have caught a fail ---------------

def productivity_link(user_id, app_name, label):
    return {"id": user_id, "appName": app_name, "label": label, "appInstanceId": "0oa1cust000000000001",
            "appAssignmentId": "0ua1cust000000000001", "hidden": False}


@pytest.mark.parametrize("loader", RUNNERS)
def test_pass_without_suite_evidence_is_not_evaluated(loader):
    body = fixture("pass")
    body.pop("orgApps")
    out = loader()(body)
    assert not_evaluated(out)
    reason = out["additionalInfo"]["dataCollection"]["errors"][0]
    assert "not shown to be assigned through Okta" in reason and "orgApps not read" in reason


@pytest.mark.parametrize("loader", RUNNERS)
@pytest.mark.parametrize("apps", [
    [],
    [{"name": "office365", "label": "Microsoft Office 365", "status": "INACTIVE"}],
    [{"name": "salesforce", "label": "Salesforce.com", "status": "ACTIVE"}],
    [{"name": "googleanalytics", "label": "Google Analytics", "status": "ACTIVE"}],
    {"errorCode": "E0000006", "statusCode": 403},
])
def test_org_apps_without_an_active_suite_are_not_evidence(loader, apps):
    body = fixture("pass")
    body["orgApps"] = apps
    assert not_evaluated(loader()(body))


@pytest.mark.parametrize("loader", RUNNERS)
@pytest.mark.parametrize("app", [
    {"name": "google", "label": "Google Apps Mail", "status": "ACTIVE"},
    {"name": "contoso_wsfed_1", "label": "Microsoft 365 (WS-Fed)", "status": "ACTIVE"},
    {"name": "template_saml_2_0", "label": "GMAIL", "status": "active"},
])
def test_active_org_suite_is_evidence(loader, app):
    body = fixture("pass")
    body["orgApps"] = {"value": [app]}
    out = loader()(body)
    assert verdict(out) is True
    assert out["additionalInfo"]["transformation"]["inputSummary"]["orgProductivityApps"] == 1


@pytest.mark.parametrize("loader", RUNNERS)
def test_non_admin_with_a_suite_link_is_evidence(loader):
    body = fixture("pass")
    body.pop("orgApps")
    body["sampleUserAppLinks"] = [[productivity_link("00u1usr0000000000009", "office365", "Microsoft Office 365")],
                                  []]
    out = loader()(body)
    assert verdict(out) is True
    assert out["additionalInfo"]["transformation"]["inputSummary"]["nonAdminUsersWithProductivityApps"] == 1


@pytest.mark.parametrize("loader", RUNNERS)
def test_sample_links_of_admins_or_failed_reads_are_not_evidence(loader):
    body = fixture("pass")
    body.pop("orgApps")
    body["sampleUserAppLinks"] = [
        [productivity_link("00u1adm0000000000001", "office365", "Microsoft Office 365")],
        {"error": True, "statusCode": 429, "item": "00u1usr0000000000009", "errorType": "rateLimited"},
        [productivity_link("00u1usr0000000000009", "salesforce", "Salesforce.com")],
    ]
    assert not_evaluated(loader()(body))


@pytest.mark.parametrize("loader", RUNNERS)
@pytest.mark.parametrize("app_name,label", [
    ("contoso_microsoft365_1", "Contoso SSO"),
    ("template_wsfed", "Microsoft 365"),
    ("template_saml_2_0", "Exchange Online"),
    ("bookmark", "Outlook Web Access"),
    ("bookmark", "Outlook"),
    ("template_wsfed", "Exchange"),
    ("bookmark", "OWA"),
    ("template_saml_2_0", "Microsoft Exchange Server"),
    ("template_saml_2_0", "G Suite"),
    ("template_saml_2_0", "Google Workspace (SAML)"),
    ("custom_gmail_app", "Mail"),
    ("OFFICE365", "Whatever"),
])
def test_custom_suite_apps_match_on_label_or_name(loader, app_name, label):
    body = fixture("pass")
    body["adminAppLinks"][1] = [productivity_link("00u1adm0000000000002", app_name, label)]
    assert verdict(loader()(body)) is False


@pytest.mark.parametrize("loader", RUNNERS)
@pytest.mark.parametrize("app_name,label", [
    ("googleanalytics", "Google Analytics"),
    ("template_saml_2_0", "Exchangerate Portal"),
    ("bookmark", "Outlookers Wiki"),
    ("gcp", "Google Cloud Console"),
    ("template_saml_2_0", "Partner Exchange"),
    ("template_saml_2_0", "Data Exchange"),
    ("bookmark", "Sales Outlook Dashboard"),
])
def test_non_suite_apps_are_not_matched(loader, app_name, label):
    body = fixture("pass")
    body["adminAppLinks"][1] = [productivity_link("00u1adm0000000000002", app_name, label)]
    assert verdict(loader()(body)) is True


# --- Review fixes: link.id is a hint, the echoed item is the pairing ---------------------------------

@pytest.mark.parametrize("loader", RUNNERS)
def test_link_id_mismatch_is_a_hint_not_a_withheld_verdict(loader):
    body = fixture("pass")
    for link in body["adminAppLinks"][0]:
        link["id"] = "00u1per0link00000001"
    out = loader()(body)
    assert verdict(out) is True
    assert any("hint only" in f for f in out["additionalInfo"]["evaluation"]["additionalFindings"])


@pytest.mark.parametrize("loader", RUNNERS)
def test_every_id_carrying_slot_mismatched_withholds_the_verdict(loader):
    # Reversed: every slot's 00u link id names the other admin and nothing echoes its user.
    body = fixture("fail")
    body["adminAppLinks"].reverse()
    out = loader()(body)
    assert not_evaluated(out)
    assert "every one of the 2" in out["additionalInfo"]["dataCollection"]["errors"][0]
    body = fixture("pass")
    for slot in body["adminAppLinks"]:
        for link in slot:
            link["id"] = "00u1somebodyelse0001"
    assert not_evaluated(loader()(body))


@pytest.mark.parametrize("loader", RUNNERS)
def test_all_mismatch_rule_skipped_when_a_slot_echoes_its_user(loader):
    body = fixture("pass")
    body["adminAppLinks"][1] = {"userId": "00u1adm0000000000002", "value": body["adminAppLinks"][1]}
    for link in body["adminAppLinks"][0]:
        link["id"] = "00u1somebodyelse0001"
    out = loader()(body)
    assert verdict(out) is True
    assert any("hint only" in f for f in out["additionalInfo"]["evaluation"]["additionalFindings"])


@pytest.mark.parametrize("loader", RUNNERS)
def test_slots_without_link_ids_are_not_counted_as_mismatched(loader):
    body = fixture("pass")
    for link in body["adminAppLinks"][0]:
        link.pop("id")
    for link in body["adminAppLinks"][1]:
        link["id"] = "00u1somebodyelse0001"
    assert not_evaluated(loader()(body))  # the only id-carrying slot mismatches
    body = fixture("pass")
    for slot in body["adminAppLinks"]:
        for link in slot:
            link.pop("id")
    assert verdict(loader()(body)) is True


# --- orgApps evidence strength (re-review of #1013) ---------------------------------------------

@pytest.mark.parametrize("loader", RUNNERS)
@pytest.mark.parametrize("signal", [{"assignedUserCount": 0}, {"_embedded": {"users": []}}, {"assignedUsers": []}])
def test_org_app_shown_unassigned_is_not_evidence(loader, signal):
    body = fixture("pass")
    body["orgApps"] = [dict({"name": "office365", "label": "Microsoft Office 365", "status": "ACTIVE"}, **signal)]
    assert not_evaluated(loader()(body))


@pytest.mark.parametrize("loader", RUNNERS)
@pytest.mark.parametrize("signal", [{"assignedUserCount": 12}, {"_embedded": {"users": [{"id": "00u1usr0000000000009"}]}}])
def test_org_app_shown_assigned_is_evidence(loader, signal):
    body = fixture("pass")
    body["orgApps"] = [dict({"name": "office365", "label": "Microsoft Office 365", "status": "ACTIVE"}, **signal)]
    out = loader()(body)
    assert verdict(out) is True
    assert out["additionalInfo"]["transformation"]["inputSummary"]["suiteEvidence"] == "assignedOrgApp"
    assert "are assigned to users" in out["additionalInfo"]["evaluation"]["passReasons"][0]


@pytest.mark.parametrize("loader", RUNNERS)
def test_org_app_without_signal_passes_with_softened_reason(loader):
    out = loader()(fixture("pass"))
    assert verdict(out) is True
    assert out["additionalInfo"]["transformation"]["inputSummary"]["suiteEvidence"] == "activeOrgApp"
    reason = out["additionalInfo"]["evaluation"]["passReasons"][0]
    assert "exists in Okta" in reason and "was not read" in reason


@pytest.mark.parametrize("loader", RUNNERS)
def test_sample_users_are_preferred_evidence(loader):
    body = fixture("pass")
    body["sampleUserAppLinks"] = [[productivity_link("00u1usr0000000000009", "office365", "Microsoft Office 365")]]
    out = loader()(body)
    assert verdict(out) is True
    assert out["additionalInfo"]["transformation"]["inputSummary"]["suiteEvidence"] == "nonAdminUsers"
    reason = out["additionalInfo"]["evaluation"]["passReasons"][0]
    assert "non-admin user" in reason and "exists in Okta" not in reason


@pytest.mark.parametrize("loader", RUNNERS)
def test_echoed_user_mismatch_gives_no_verdict(loader):
    body = fixture("fail")
    body["adminAppLinks"][0] = {"error": True, "statusCode": 500, "item": "00u1usr0000000000003",
                                "errorType": "vendorError"}
    assert not_evaluated(loader()(body))
    body = fixture("fail")
    body["adminAppLinks"][0] = {"userId": "00u1usr0000000000003", "value": body["adminAppLinks"][0]}
    assert not_evaluated(loader()(body))


@pytest.mark.parametrize("loader", RUNNERS)
def test_matching_echoed_user_is_paired(loader):
    body = fixture("pass")
    body["adminAppLinks"][0] = {"userId": "00u1adm0000000000001", "value": body["adminAppLinks"][0]}
    assert verdict(loader()(body)) is True


@pytest.mark.parametrize("loader", RUNNERS)
@pytest.mark.parametrize("label", ["Partner Exchange", "Data Exchange", "Market Outlook"])
def test_ambiguous_org_apps_are_not_pass_evidence(loader, label):
    body = fixture("pass")
    body["orgApps"] = [{"name": "template_saml_2_0", "label": label, "status": "ACTIVE"}]
    assert not_evaluated(loader()(body))
