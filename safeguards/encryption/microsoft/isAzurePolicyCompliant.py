# isAzurePolicyCompliant.py
# Azure Key Vault - AM-2.1: Approved Services - Azure Policy Compliance
"""
isAzurePolicyCompliant

Criterion: no Azure Policy assignment reports the vault non-compliant.

Data source: getPolicyStates -- POST https://management.azure.com/{vaultResourceId}/providers
/Microsoft.PolicyInsights/policyStates/latest/queryResults?api-version=2019-10-01
&$filter=complianceState eq 'NonCompliant'
(https://learn.microsoft.com/en-us/rest/api/policyinsights/policy-states/list-query-results-for-resource?view=rest-policyinsights-2019-10-01).
The query is filtered to NonCompliant, so value lists only non-compliant states and an empty
value array is the vendor saying there are none. @odata.count is the total.

  true  = value is an empty list and @odata.count is absent or zero
  false = value lists a non-compliant state, or @odata.count is above zero
  None  = no value list, an Azure error, or an exception

Every unmeasured path returns None, and respond() derives dataCollection.status from that value,
so an error body, an empty body or this file's own exception is Not evaluated, never a
measured false.
"""
import json
import ast
from datetime import datetime, timezone

KEY = "isAzurePolicyCompliant"
VENDOR = "Microsoft Azure Key Vault"
CATEGORY = "Encryption"
METHOD = "getPolicyStates"


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        # "data" last: the {"data": ..., "validation": ...} pair is handled above, so this only
        # catches a bare {"data": {...}} wrapper. Every one of these files unwrapped that on main
        # and nothing has confirmed which shape Integration-Service actually sends, because these
        # checks have never run live. Dropping it would silently turn a verdict into Not evaluated.
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output", "rawResponse",
                        "data"]
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


def load(input):
    if isinstance(input, bytes):
        input = input.decode("utf-8")
    if isinstance(input, str):
        if not input.strip():
            input = None
        else:
            try:
                input = json.loads(input)
            except Exception:
                input = ast.literal_eval(input)
    return extract_input(input)


def respond(value, reason, validation=None, extra=None, recommendations=None, transformation_errors=None):
    """The one exit. Whether the criterion was measured is read off the value: None, and
    only None, is not measured, and that alone sets dataCollection.status to "error", which
    is what Token-Service reads to grade a criterion Not evaluated."""
    result = {KEY: value}
    for name in (extra or {}):
        result[name] = extra[name]
    measured = value is not None
    passed = value is True
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "success" if measured else "error", "errors": [] if measured else [reason]},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []),
                           "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if transformation_errors else "success",
                               "errors": transformation_errors or [], "inputSummary": extra or {}},
            "evaluation": {"passReasons": [reason] if passed else [], "failReasons": [] if passed else [reason],
                           "recommendations": [] if passed else (recommendations or []), "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.now(timezone.utc).isoformat(), "schemaVersion": "2.0",
                         "transformationId": KEY, "vendor": VENDOR, "category": CATEGORY, "method": METHOD},
        },
    }


def error_reason(data):
    """Why this body is not an Azure answer, or None. Azure Resource Manager and the Key Vault
    data plane both fail with {"error": {"code": ..., "message": ...}}."""
    if not isinstance(data, dict):
        return "the response is not a JSON object"
    err = data.get("error")
    if err:
        if isinstance(err, dict):
            return "Azure returned an error: " + str(err.get("code") or "") + " " + str(err.get("message") or "")[:200]
        return "Azure returned an error: " + str(err)[:200]
    if data.get("errors") or data.get("vendorErrorAsResponse"):
        return "the response is an error envelope"
    status = data.get("statusCode") or data.get("status_code")
    if isinstance(status, int) and status >= 400:
        return "the response carries HTTP status " + str(status)
    return None


def evaluate(data, validation):
    if "value" not in data:
        return respond(None, "No policy compliance data returned", validation)
    states = data.get("value")
    if not isinstance(states, list):
        return respond(None, "Unexpected value shape in the policy states response", validation)
    count = data.get("@odata.count")
    total = count if isinstance(count, int) and not isinstance(count, bool) else len(states)
    extra = {"nonCompliantPolicyStates": max(total, len(states))}
    if total > 0 or len(states) > 0:
        return respond(False, str(max(total, len(states))) + " non-compliant policy state(s) for the vault",
                       validation, extra, ["Remediate the non-compliant Azure Policy assignments on the vault"])
    return respond(True, "No Azure Policy assignment reports the vault non-compliant", validation, extra)


def transform(input):
    try:
        data, validation = load(input)
        why = error_reason(data)
        if why:
            return respond(None, why, validation)
        return evaluate(data, validation)
    except Exception as e:
        return respond(None, "Transformation error: " + str(e)[:300], None, {"error": str(e)[:300]},
                       transformation_errors=[str(e)[:300]])
