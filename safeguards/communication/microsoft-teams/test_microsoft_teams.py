"""Microsoft Teams (Communication): confirmedLicensePurchased, isTeamsEnabled.

Fixtures follow https://learn.microsoft.com/en-us/graph/api/subscribedsku-list?view=graph-rest-1.0 and
https://learn.microsoft.com/en-us/graph/api/teamwork-get?view=graph-rest-1.0 .
"""
import importlib.util
from pathlib import Path

import pytest


def load(name):
    spec = importlib.util.spec_from_file_location("teams_" + name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


LICENSE = load("confirmedLicensePurchased")
ENABLED = load("isTeamsEnabled")


def sku(part, plans, enabled=25, consumed=14, status="Enabled"):
    return {"skuId": part + "-id", "skuPartNumber": part, "capabilityStatus": status, "consumedUnits": consumed,
            "prepaidUnits": {"enabled": enabled, "lockedOut": 0, "suspended": 0, "warning": 0},
            "servicePlans": [{"servicePlanName": p, "provisioningStatus": "Success"} for p in plans]}


def skus(*items):
    return {"@odata.context": "https://graph.microsoft.com/v1.0/$metadata#subscribedSkus", "value": list(items)}


def run(module, key, payload):
    out = module.transform(payload)
    return out["transformedResponse"][key], out["additionalInfo"]["dataCollection"]["status"]


def test_teams_licence_counts_seats():
    body = skus(sku("SPE_E3", ["EXCHANGE_S_ENTERPRISE", "TEAMS1"], enabled=40, consumed=31), sku("CRMSTANDARD", ["CRMSTANDARD"]))
    assert run(LICENSE, "confirmedLicensePurchased", body) == (True, "success")
    out = LICENSE.transform(body)["transformedResponse"]
    assert (out["teamsLicensedSeats"], out["teamsConsumedUnits"]) == (40, 31)


def test_no_teams_plan_is_measured_false():
    assert run(LICENSE, "confirmedLicensePurchased", skus(sku("CRMSTANDARD", ["CRMSTANDARD"]))) == (False, "success")


def test_suspended_or_zero_seat_teams_sku_does_not_count():
    body = skus(sku("SPE_E3", ["TEAMS1"], status="Suspended"), sku("M365_BIZ", ["TEAMS1"], enabled=0))
    assert run(LICENSE, "confirmedLicensePurchased", body) == (False, "success")


def test_teams_enabled_and_disabled():
    assert run(ENABLED, "isTeamsEnabled", {"id": "teamwork", "isTeamsEnabled": True, "region": "Americas"}) == (True, "success")
    assert run(ENABLED, "isTeamsEnabled", {"id": "teamwork", "isTeamsEnabled": False}) == (False, "success")


NO_EVIDENCE = {
    "null": None,
    "empty_dict": {},
    "empty_string": "",
    "graph_403": {"error": {"code": "Authorization_RequestDenied", "message": "Insufficient privileges"}},
    "auth_401": {"statusCode": 401, "error": "Unauthorized"},
    "unrelated": {"hello": "world"},
}


@pytest.mark.parametrize("name", sorted(NO_EVIDENCE))
def test_licence_no_evidence(name):
    assert run(LICENSE, "confirmedLicensePurchased", NO_EVIDENCE[name]) == (None, "error")


@pytest.mark.parametrize("name", sorted(NO_EVIDENCE))
def test_enabled_no_evidence(name):
    assert run(ENABLED, "isTeamsEnabled", NO_EVIDENCE[name]) == (None, "error")


def test_paged_sku_list_is_unmeasured():
    body = skus(sku("SPE_E3", ["TEAMS1"]))
    body["@odata.nextLink"] = "https://graph.microsoft.com/v1.0/subscribedSkus?$skiptoken=x"
    assert run(LICENSE, "confirmedLicensePurchased", body) == (None, "error")


def test_string_flag_is_not_a_boolean():
    assert run(ENABLED, "isTeamsEnabled", {"id": "teamwork", "isTeamsEnabled": "true"}) == (None, "error")
