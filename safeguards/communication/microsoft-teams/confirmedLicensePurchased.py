"""
Transformation: confirmedLicensePurchased
Vendor: Microsoft Teams  |  Category: Communication

Criterion: the tenant holds an active licence that includes Microsoft Teams.

Data source: getLicenseInfo --
GET https://graph.microsoft.com/v1.0/subscribedSkus
(https://learn.microsoft.com/en-us/graph/api/subscribedsku-list?view=graph-rest-1.0, application permission
LicenseAssignment.Read.All). A SKU counts when capabilityStatus is Enabled, prepaidUnits.enabled > 0 and one
of its servicePlans is a Teams plan (servicePlanName starting TEAMS, e.g. TEAMS1, TEAMS_GOV) whose
provisioningStatus is not Disabled. Not counted, because they are not a purchased Teams licence: free and trial
SKUs (skuPartNumber containing TRIAL, FREE or EXPLORATORY -- TEAMS_FREE, TEAMS_EXPLORATORY, ..._TRIAL), the
TEAMS_FREE plan, and the TEAMSPRO_* Teams Premium add-on plans. Service plan names:
https://learn.microsoft.com/en-us/entra/identity/users/licensing-service-plan-reference .

Returns teamsLicensedSeats (sum of prepaidUnits.enabled) and teamsConsumedUnits over those SKUs. A tenant
with SKUs but none carrying Teams is a measured false. Fails closed: an error body, no value list, or a
paged list (@odata.nextLink) returns None.
"""
import json
from datetime import datetime

KEY = "confirmedLicensePurchased"
VENDOR = "Microsoft Teams"
CATEGORY = "Communication"


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output", "rawResponse"]
        for i in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None, recommendations=None,
                    input_summary=None, api_errors=None, transformation_errors=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []),
                           "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success",
                               "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                           "recommendations": recommendations or [], "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "2.0",
                         "transformationId": KEY, "vendor": VENDOR, "category": CATEGORY},
        },
    }


def not_measured(reason, validation=None):
    return create_response(result={KEY: None}, validation=validation, api_errors=[reason], fail_reasons=[reason])


def as_count(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, float) and value == int(value) and value >= 0:
        return int(value)
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def is_error_body(data):
    if not isinstance(data, dict):
        return False
    if data.get("error") or data.get("errors"):
        return True
    status = data.get("statusCode") or data.get("status_code") or data.get("status")
    if isinstance(status, int) and status >= 400:
        return True
    return False


def load(input):
    if isinstance(input, bytes):
        input = input.decode("utf-8")
    if isinstance(input, str):
        input = json.loads(input) if input.strip() else None
    return extract_input(input)


NOT_PURCHASED_MARKERS = ["TRIAL", "FREE", "EXPLORATORY"]


def is_teams_plan(plan):
    """A Teams service plan the SKU actually provisions: TEAMS1, TEAMS_GOV, TEAMS_AR_GCCHIGH, TEAMS_AR_DOD ...

    Not TEAMS_FREE (Teams free), not the TEAMSPRO_* Teams Premium add-on plans (they need a base Teams licence and
    do not grant Teams), and not a plan whose provisioningStatus is Disabled (Teams switched off in that SKU).
    """
    if not isinstance(plan, dict):
        return False
    name = str(plan.get("servicePlanName") or "").upper()
    if not name.startswith("TEAMS") or name.startswith("TEAMSPRO") or "FREE" in name:
        return False
    return str(plan.get("provisioningStatus") or "") != "Disabled"


def is_teams_sku(sku):
    if str(sku.get("capabilityStatus") or "") != "Enabled":
        return False
    part = str(sku.get("skuPartNumber") or "").upper()
    for marker in NOT_PURCHASED_MARKERS:
        if marker in part:
            return False
    for plan in sku.get("servicePlans") or []:
        if is_teams_plan(plan):
            return True
    return False


def transform(input):
    try:
        data, validation = load(input)
        if is_error_body(data):
            return not_measured("Microsoft Graph returned an error for subscribedSkus", validation)
        skus = data.get("value") if isinstance(data, dict) else None
        if not isinstance(skus, list) or data.get("@odata.nextLink"):
            return not_measured("No complete subscribedSkus list was returned", validation)
        seats = 0
        consumed = 0
        names = []
        for sku in skus:
            if not isinstance(sku, dict) or not sku.get("skuId") or not is_teams_sku(sku):
                continue
            prepaid = sku.get("prepaidUnits") if isinstance(sku.get("prepaidUnits"), dict) else {}
            enabled = as_count(prepaid.get("enabled"))
            if not enabled:
                continue
            seats = seats + enabled
            consumed = consumed + (as_count(sku.get("consumedUnits")) or 0)
            names.append(str(sku.get("skuPartNumber") or sku.get("skuId")))
        result = {KEY: seats > 0, "teamsLicensedSeats": seats, "teamsConsumedUnits": consumed,
                  "subscribedSkuCount": len(skus)}
        if seats > 0:
            return create_response(result=result, validation=validation, input_summary=result,
                                   pass_reasons=[str(seats) + " enabled seats include Teams (" + ", ".join(names) + ")"])
        return create_response(result=result, validation=validation, input_summary=result,
                               fail_reasons=["No enabled subscription includes a Teams service plan"])
    except Exception as e:
        return create_response(result={KEY: None}, transformation_errors=[str(e)],
                               api_errors=["Transformation error: " + str(e)],
                               fail_reasons=["Transformation error: " + str(e)])
