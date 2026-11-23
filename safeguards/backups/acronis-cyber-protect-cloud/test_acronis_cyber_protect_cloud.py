"""Acronis Cyber Protect Cloud: licence and machine-backup checks.

Shapes follow Acronis's published platform samples (offering items: application_id, status 1/0, edition,
tenant_id; tenant: id, enabled, kind, pricing_mode trial/production/suspended; API client: tenant_id) and
the resource_statuses item shape (context, aggregate.status, policies[].type / last_success_run) read by
the Zabbix Acronis Cyber Protect Cloud template. Synthetic data only: made-up GUIDs and names.
"""
import copy
import importlib.util
import json
import os
from datetime import datetime, timedelta, timezone

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))

TENANT = "11111111-2222-4333-8444-555555555555"
OTHER = "99999999-8888-4777-8666-555555555555"
CLIENT = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
CP_APP = "6e6d758d-8e74-3ae3-ac84-50eb0dff12eb"
OTHER_APP = "f00df00d-0000-4000-8000-000000000001"


def load(name):
    spec = importlib.util.spec_from_file_location("acronis_cpc_" + name, os.path.join(HERE, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


LICENCE = load("confirmedlicensepurchased")
BACKUP = load("arebackupsenabledforcriticalsystems")


def lic(body):
    out = LICENCE(body)
    return out["transformedResponse"]["confirmedLicensePurchased"], out


def bak(body):
    out = BACKUP(body)
    return out["transformedResponse"]["areBackupsEnabledForCriticalSystems"], out


def ts_wrap(body):
    return {"data": {"apiResponse": body}, "validation": {"status": "skipped", "errors": [], "warnings": []}}


def item(app=CP_APP, status=1, edition="per_workload", tenant=TENANT, name="workstations"):
    return {"application_id": app, "name": name, "edition": edition, "usage_name": name, "tenant_id": tenant,
            "updated_at": "2026-01-01T00:00:00Z", "status": status, "locked": False, "type": "count",
            "measurement_unit": "quantity", "quota": {"value": None, "overage": None, "version": 1}}


def licence_body(mode="production", enabled=True, items=None, paging=None):
    offering = {"items": [item()] if items is None else items}
    if paging is not None:
        offering["paging"] = paging
    return {
        "client": {"client_id": CLIENT, "tenant_id": TENANT, "type": "api_client", "status": "enabled",
                   "data": {"client_name": "Example client"}},
        "tenant": {"id": TENANT, "name": "Example Co", "kind": "customer", "enabled": enabled, "pricing_mode": mode},
        "offeringItems": offering,
    }


def assert_not_measured(out):
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"
    assert out["additionalInfo"]["dataCollection"]["errors"]


# --- confirmedLicensePurchased ---------------------------------------------------------------

def test_licence_paid_tenant_with_protection_on_passes():
    value, out = lic(licence_body())
    assert value is True
    assert out["transformedResponse"]["protectionOfferingItemsOn"] == 1
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"


def test_licence_through_token_service_wrapper():
    assert lic(ts_wrap(licence_body()))[0] is True
    assert lic({"apiResponse": json.dumps(licence_body())})[0] is True


@pytest.mark.parametrize("mode", ["trial", "suspended", "TRIAL"])
def test_licence_trial_or_suspended_fails(mode):
    value, out = lic(licence_body(mode=mode))
    assert value is False
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"


def test_licence_disabled_tenant_fails():
    assert lic(licence_body(enabled=False))[0] is False


def test_licence_protection_item_off_fails():
    value, out = lic(licence_body(items=[item(status=0), item(app=OTHER_APP)]))
    assert value is False
    assert "turned on" in out["additionalInfo"]["evaluation"]["failReasons"][0]


def test_licence_no_protection_item_fails():
    assert lic(licence_body(items=[item(app=OTHER_APP)]))[0] is False
    assert lic(licence_body(items=[]))[0] is False


def test_licence_other_tenants_items_do_not_count():
    assert lic(licence_body(items=[item(tenant=OTHER)]))[0] is False


def test_licence_partial_list_with_nothing_on_is_not_measured():
    value, out = lic(licence_body(items=[item(status=0)], paging={"cursors": {"after": "abc"}}))
    assert value is None
    assert_not_measured(out)


def test_licence_partial_list_with_an_item_on_still_passes():
    assert lic(licence_body(paging={"cursors": {"after": "abc"}}))[0] is True


@pytest.mark.parametrize("mutate", [
    lambda b: b["tenant"].update(pricing_mode="something_new"),
    lambda b: b["tenant"].pop("pricing_mode"),
    lambda b: b["tenant"].pop("enabled"),
    lambda b: b["tenant"].update(id=OTHER),
    lambda b: b["client"].pop("tenant_id"),
    lambda b: b["client"].update(tenant_id="not-a-uuid"),
    lambda b: b.pop("offeringItems"),
    lambda b: b.pop("tenant"),
    lambda b: b.pop("client"),
    lambda b: b["offeringItems"].pop("items"),
    lambda b: b["offeringItems"]["items"].append("junk"),
    lambda b: b["offeringItems"]["items"][0].update(status=True),
    lambda b: b.update(offeringItems={"error": {"code": 403, "message": "Forbidden"}}),
])
def test_licence_unrecognised_shapes_are_not_measured(mutate):
    body = licence_body()
    mutate(body)
    value, out = lic(body)
    assert value is None
    assert_not_measured(out)


CONSOLE_HTML = b"<!DOCTYPE html><html><head><title>Login</title></head><body>console</body></html>"


@pytest.mark.parametrize("body", [
    None, {}, "", "{}", [], CONSOLE_HTML, CONSOLE_HTML.decode(), {"apiResponse": CONSOLE_HTML},
    {"error": True, "errorType": "authentication", "statusCode": 401, "status": "Error"},
    {"apiResponse": {"statusCode": 403, "status": "Error", "message": "x"}},
])
def test_licence_no_evidence_is_not_measured(body):
    value, out = lic(body)
    assert value is None
    assert_not_measured(out)


# --- areBackupsEnabledForCriticalSystems ----------------------------------------------------

def iso(days_ago, offset=""):
    t = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return t.strftime("%Y-%m-%dT%H:%M:%S") + (offset or "Z")


def machine(name, last_success_days=1, backup=True, status="ok", extra_policies=None, rtype="resource.machine",
            last_success=None):
    policies = []
    if backup:
        policies.append({"id": name + "-plan", "type": "policy.backup.machine",
                         "last_run": iso(0.5), "next_run": iso(-1),
                         "last_success_run": last_success if last_success is not None else
                         (iso(last_success_days) if last_success_days is not None else None)})
    policies = policies + (extra_policies or [])
    return {"context": {"id": name + "-id", "name": name, "type": rtype},
            "aggregate": {"status": status, "names": [name + " plan"]}, "policies": policies}


def statuses(items, paging=None):
    body = {"items": items}
    if paging is not None:
        body["paging"] = paging
    return {"machineStatuses": body}


def test_backup_every_machine_recent_passes():
    value, out = bak(statuses([machine("ws-01"), machine("srv-01", 6)]))
    assert value is True
    assert out["transformedResponse"]["machineCount"] == 2
    assert bak(ts_wrap(statuses([machine("ws-01")])))[0] is True


def test_backup_offset_and_fractional_timestamps_read():
    assert bak(statuses([machine("ws-01", last_success=iso(1, "+02:00"))]))[0] is True
    stamp = (datetime.now(timezone.utc) - timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%S.123456Z")
    assert bak(statuses([machine("ws-01", last_success=stamp)]))[0] is True


def test_backup_machine_without_backup_plan_fails():
    av = [{"type": "policy.security.antimalware_protection", "last_success_run": iso(1)}]
    value, out = bak(statuses([machine("ws-01"), machine("ws-02", backup=False, extra_policies=av)]))
    assert value is False
    assert out["transformedResponse"]["unprotectedMachines"] == 1
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"


def test_backup_not_protected_machine_fails():
    assert bak(statuses([machine("ws-01"), machine("ws-02", backup=False, status="not_protected")]))[0] is False


def test_backup_stale_or_never_fails():
    assert bak(statuses([machine("ws-01"), machine("ws-02", 30)]))[0] is False
    assert bak(statuses([machine("ws-01"), machine("ws-02", None)]))[0] is False


def test_backup_non_machine_resources_are_ignored():
    mailbox = machine("mbx-01", backup=False, rtype="resource.mailbox")
    assert bak(statuses([machine("ws-01"), mailbox]))[0] is True


def test_backup_failure_wins_over_unreadable():
    assert bak(statuses([machine("ws-01", 30), machine("ws-02", last_success="yesterday-ish")]))[0] is False


@pytest.mark.parametrize("body", [
    statuses([]),
    statuses([machine("mbx-01", rtype="resource.mailbox")]),
    statuses([machine("ws-01")], paging={"cursors": {"after": "next-page"}}),
    statuses([machine("ws-01")], paging={"cursors": {"after": None, "truncated": True}}),
    statuses([machine("ws-01", last_success="yesterday-ish")]),
    statuses([machine("ws-01", last_success=iso(-5))]),
    statuses(["junk"]),
    {"machineStatuses": {"items": None}},
    {"machineStatuses": {"error": {"code": 403, "message": "Forbidden"}}},
    {"machineStatuses": {"items": [machine("ws-01")]}, "paginationTruncated": True},
    {"other": {}},
])
def test_backup_unrecognised_or_partial_is_not_measured(body):
    value, out = bak(body)
    assert value is None
    assert_not_measured(out)


def test_backup_policies_not_a_list_is_not_measured():
    m = machine("ws-01")
    m["policies"] = "x"
    assert bak(statuses([m]))[0] is None


@pytest.mark.parametrize("body", [
    None, {}, "", "{}", [], CONSOLE_HTML, CONSOLE_HTML.decode(), {"apiResponse": CONSOLE_HTML},
    {"error": True, "errorType": "authentication", "statusCode": 401, "status": "Error"},
])
def test_backup_no_evidence_is_not_measured(body):
    value, out = bak(body)
    assert value is None
    assert_not_measured(out)


def test_inputs_are_not_mutated():
    body = statuses([machine("ws-01")])
    before = copy.deepcopy(body)
    bak(body)
    assert body == before
    lb = licence_body()
    lbefore = copy.deepcopy(lb)
    lic(lb)
    assert lb == lbefore


# --- isBackupEnabledForCriticalSystems / isBackupEnabled (platform-standard Backup keys) -------

CRITICAL = load("isbackupenabledforcriticalsystems")
ENABLED = load("isbackupenabled")


def crit(body):
    out = CRITICAL(body)
    return out["transformedResponse"]["isBackupEnabledForCriticalSystems"], out


def ena(body):
    out = ENABLED(body)
    return out["transformedResponse"]["isBackupEnabled"], out


PARTIAL = {"cursors": {"after": "next-page"}}

STANDARD_CASES = [
    # body, isBackupEnabledForCriticalSystems, isBackupEnabled
    (statuses([machine("ws-01"), machine("srv-01", 6)]), True, True),
    (ts_wrap(statuses([machine("ws-01")])), True, True),
    (statuses([machine("ws-01"), machine("ws-02", backup=False)]), False, True),
    (statuses([machine("ws-01"), machine("ws-02", 30)]), False, True),
    (statuses([machine("ws-01", 30), machine("ws-02", None)]), False, False),
    (statuses([machine("ws-01", backup=False, status="not_protected")]), False, False),
    (statuses([machine("ws-01", 30), machine("ws-02", last_success="yesterday-ish")]), False, None),
    (statuses([machine("ws-01")], paging=PARTIAL), None, True),
    (statuses([machine("ws-01", 30)], paging=PARTIAL), None, None),
    (statuses([machine("mbx-01", rtype="resource.mailbox")]), None, None),
    (statuses([]), None, None),
    (statuses([machine("ws-01", last_success=iso(-5))]), None, None),
    (statuses(["junk"]), None, None),
    ({"machineStatuses": {"items": None}}, None, None),
    ({"machineStatuses": {"error": {"code": 403, "message": "Forbidden"}}}, None, None),
    ({"machineStatuses": {"items": [machine("ws-01")]}, "paginationTruncated": True}, None, None),
    ({"other": {}}, None, None),
    (None, None, None),
    ({}, None, None),
    ("", None, None),
    ("{}", None, None),
    ([], None, None),
    (CONSOLE_HTML, None, None),
    (CONSOLE_HTML.decode(), None, None),
    ({"apiResponse": CONSOLE_HTML}, None, None),
    ({"error": True, "errorType": "authentication", "statusCode": 401, "status": "Error"}, None, None),
]


@pytest.mark.parametrize("body,want_crit,want_enabled", STANDARD_CASES)
def test_standard_backup_keys(body, want_crit, want_enabled):
    got_crit, out_crit = crit(body)
    got_enabled, out_enabled = ena(body)
    assert got_crit is want_crit
    assert got_enabled is want_enabled
    for value, out in ((got_crit, out_crit), (got_enabled, out_enabled)):
        if value is None:
            assert_not_measured(out)
        else:
            assert out["additionalInfo"]["dataCollection"]["status"] == "success"


def test_critical_key_matches_the_aggregate_key():
    for body, _, _ in STANDARD_CASES:
        assert crit(body)[0] is bak(body)[0]


def test_standard_keys_only_answer_their_own_key():
    assert set(crit(statuses([machine("ws-01")]))[1]["transformedResponse"]) >= {"isBackupEnabledForCriticalSystems"}
    assert "areBackupsEnabledForCriticalSystems" not in crit(statuses([machine("ws-01")]))[1]["transformedResponse"]
    assert "isBackupEnabledForCriticalSystems" not in ena(statuses([machine("ws-01")]))[1]["transformedResponse"]


def test_standard_keys_do_not_mutate_input():
    body = statuses([machine("ws-01"), machine("ws-02", 30)], paging=PARTIAL)
    before = copy.deepcopy(body)
    crit(body)
    ena(body)
    assert body == before
