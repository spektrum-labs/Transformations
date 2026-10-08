"""
Transformation: isNonHumanIdentityInventoryEnabled
Vendor: JumpCloud  |  Category: Identity and Access Management

Criterion (bundle 133571e9, requirement ad617c04): "Service Accounts (machine identities) are
enumerable via the API as a distinct inventory."

Data source: GET https://console.jumpcloud.com/api/v2/service-accounts (IS method listServiceAccounts,
offset-paged on limit/skip, dataPath "results"). JumpCloud API 2.0, operation
ServiceAccounts_ListServiceAccounts -- https://docs.jumpcloud.com/api/2.0/index.html (spec:
https://docs.jumpcloud.com/api/2.0/index.yaml, schema jumpcloud.service_accounts.ListServiceAccountsResponse:
{"results": [ServiceAccount], "totalCount": int}). Listing requires an admin with the Administrator With
Billing role or a custom role carrying the Service Accounts scope
(https://jumpcloud.com/support/service-account-for-apis).

Verdict:
  True   the full inventory was read and at least one service account is registered, so machine
         identities are held as their own inventory rather than as human admins' API keys.
  False  the full inventory was read and it is empty: no machine identity is inventoried separately.
  None   (Unevaluated, dataCollection error) anything that is not a complete service-account list:
         null, {}, an error/403 envelope, unrelated JSON, records that are not objects, or a read that
         returned fewer records than totalCount.
"""
import json
from datetime import datetime

KEY = "isNonHumanIdentityInventoryEnabled"
META = {"transformationId": KEY, "vendor": "JumpCloud", "category": "identity-and-access-management"}


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for _ in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), (dict, list)):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped or not isinstance(data, dict):
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format - no schema validation performed"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None, recommendations=None,
                    input_summary=None, api_errors=None, transformation_errors=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    metadata = {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "2.0"}
    metadata.update(META)
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
            "metadata": metadata,
        },
    }


def unevaluated(problem, validation=None):
    return create_response(result={KEY: None}, validation=validation, fail_reasons=[problem], api_errors=[problem])


def as_count(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def service_accounts(data):
    """(records, problem). records is the complete list or None."""
    if not isinstance(data, dict):
        return None, "No JumpCloud service-account list in the response; nothing to evaluate."
    records = data.get("results")
    if not isinstance(records, list):
        return None, "No JumpCloud service-account list in the response; nothing to evaluate."
    if not all(isinstance(r, dict) for r in records):
        return None, "The response is not a list of JumpCloud service-account records."
    total = as_count(data.get("totalCount"))
    if total is None:
        return None, "The service-account list carries no totalCount; completeness cannot be confirmed."
    if len(records) < total:
        return None, ("Only " + str(len(records)) + " of " + str(total) +
                      " service accounts were read; a partial inventory is not evaluated.")
    return records, None


def transform(input):
    try:
        if isinstance(input, str):
            input = json.loads(input) if input.strip() else None
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        records, problem = service_accounts(data)
        if problem:
            return unevaluated(problem, validation)
        count = len(records)
        summary = {"serviceAccountCount": count}
        if count > 0:
            return create_response(
                result={KEY: True, "serviceAccountCount": count}, validation=validation,
                pass_reasons=[str(count) + " JumpCloud service account(s) are registered and enumerable via "
                              "GET /api/v2/service-accounts as a distinct machine-identity inventory"],
                input_summary=summary)
        return create_response(
            result={KEY: False, "serviceAccountCount": 0}, validation=validation,
            fail_reasons=["No JumpCloud service accounts are registered; machine access is not inventoried "
                          "separately from human administrators"],
            recommendations=["Create JumpCloud Service Accounts for API integrations instead of administrator API keys"],
            input_summary=summary)
    except Exception as e:
        return create_response(result={KEY: None}, transformation_errors=[str(e)],
                               api_errors=["Transformation error: " + str(e)],
                               fail_reasons=["Transformation error: " + str(e)])
