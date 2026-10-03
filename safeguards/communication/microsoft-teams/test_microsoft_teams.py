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


def test_free_and_trial_teams_skus_are_not_purchased():
    body = skus(sku("TEAMS_EXPLORATORY", ["TEAMS1"], enabled=100), sku("TEAMS_FREE", ["TEAMS_FREE"], enabled=500000),
                sku("SPE_E5_TRIAL", ["TEAMS1"], enabled=25))
    assert run(LICENSE, "confirmedLicensePurchased", body) == (False, "success")


def test_premium_addon_alone_or_disabled_plan_is_not_teams():
    premium = sku("Microsoft_Teams_Premium", ["TEAMSPRO_CUST", "TEAMSPRO_PROTECTION"])
    no_teams = sku("SPE_E3", ["EXCHANGE_S_ENTERPRISE", "TEAMS1"])
    no_teams["servicePlans"][1]["provisioningStatus"] = "Disabled"
    assert run(LICENSE, "confirmedLicensePurchased", skus(premium, no_teams)) == (False, "success")


def test_gov_teams_plan_counts():
    assert run(LICENSE, "confirmedLicensePurchased", skus(sku("SPE_E3_USGOV_GCCHIGH", ["TEAMS_AR_GCCHIGH"]))) == (True, "success")


def test_schema_version_is_2():
    assert LICENSE.transform(skus(sku("SPE_E3", ["TEAMS1"])))["additionalInfo"]["metadata"]["schemaVersion"] == "2.0"
    assert ENABLED.transform({"isTeamsEnabled": True})["additionalInfo"]["metadata"]["schemaVersion"] == "2.0"


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
    "not_found_404": {"statusCode": 404, "error": "Not Found"},
    "pagination_incomplete": {"error": True, "errorType": "pagination_incomplete", "status": "Error", "statusCode": 429},
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


def test_every_transform_reports_schema_version_2_0():
    """transformedResponse envelope is the CONTRIBUTING.md schemaVersion 2.0 one, on answers and on errors."""
    import importlib.util as iu
    for path in sorted(Path(__file__).parent.glob("*.py")):
        if path.name.startswith("test_"):
            continue
        spec = iu.spec_from_file_location("schema_" + path.stem, path)
        module = iu.module_from_spec(spec)
        spec.loader.exec_module(module)
        out = module.transform({})
        assert out["additionalInfo"]["metadata"]["schemaVersion"] == "2.0", path.name
        assert set(out["additionalInfo"]) == {"dataCollection", "validation", "transformation", "evaluation", "metadata"}
