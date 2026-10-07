# isDefenderForKeyVaultEnabled.py
# Azure Key Vault - LT-1.1: Threat Detection - Microsoft Defender for Key Vault
"""
isDefenderForKeyVaultEnabled

Criterion: Microsoft Defender for Key Vault is enabled on the vault's subscription.

Data source: getDefenderPricing -- GET https://management.azure.com/subscriptions/{subscriptionId}
/providers/Microsoft.Security/pricings/KeyVaults?api-version=2024-01-01
(https://learn.microsoft.com/en-us/rest/api/defenderforcloud/pricings/get?view=rest-defenderforcloud-2024-01-01).
properties.pricingTier is the PricingTier enum Free | Standard: "Indicates whether the Defender
plan is enabled on the selected scope." The plan is set per subscription.

  true  = properties.pricingTier is "Standard"
  false = it is "Free"
  None  = no pricingTier (it used to default to "Free", so an error body read as a measured
          false), a pricing for a plan other than KeyVaults, an Azure error, or an exception

Every unmeasured path returns None, and respond() derives dataCollection.status from that value,
so an error body, an empty body or this file's own exception is Not evaluated, never a
measured false.
"""
import json
import ast
from datetime import datetime, timezone

KEY = "isDefenderForKeyVaultEnabled"
VENDOR = "Microsoft Azure Key Vault"
CATEGORY = "Encryption"
METHOD = "getDefenderPricing"


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
    props = data.get("properties")
    tier = props.get("pricingTier") if isinstance(props, dict) else None
    name = data.get("name")
    if isinstance(name, str) and name.lower() != "keyvaults":
        return respond(None, "The pricing returned is for the " + name + " plan, not KeyVaults", validation)
    extra = {"pricingTier": tier, "subPlan": props.get("subPlan") if isinstance(props, dict) else None}
    if tier == "Standard":
        return respond(True, "Defender for Key Vault pricingTier is Standard", validation, extra)
    if tier == "Free":
        return respond(False, "Defender for Key Vault pricingTier is Free: the plan is off", validation, extra,
                       ["Enable the Microsoft Defender for Key Vault plan on the subscription"])
    return respond(None, "The response carries no Defender pricingTier (got " + str(tier) + ")", validation)


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
