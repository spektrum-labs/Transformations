# isPurgeProtectionEnabled.py
# Azure Key Vault - DP-6.2: Key Management - Purge Protection Enabled
"""
isPurgeProtectionEnabled

Criterion: purge protection is enabled on the vault.

Data source: getVaultProperties -- GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.KeyVault/vaults/{vaultName}?api-version=2023-07-01
(https://learn.microsoft.com/en-us/rest/api/keyvault/keyvault/vaults/get?view=rest-keyvault-keyvault-2023-07-01). properties.enablePurgeProtection: "Enabling this functionality is irreversible -
that is, the property does not accept false as its value." Purge protection "is not enabled by
default" (https://learn.microsoft.com/en-us/azure/key-vault/general/soft-delete-overview), so an
absent value on a vault body is a vault without it.

  true  = enablePurgeProtection is true
  false = it is absent or not true
  None  = not a Key Vault body, an Azure error, or an exception

Every unmeasured path returns None, and respond() derives dataCollection.status from that value,
so an error body, an empty body or this file's own exception is Not evaluated, never a
measured false.
"""
import json
import ast
from datetime import datetime, timezone

KEY = "isPurgeProtectionEnabled"
VENDOR = "Microsoft Azure Key Vault"
CATEGORY = "Encryption"
METHOD = "getVaultProperties"


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


def vault_properties(data):
    """The vault's properties, or None when this is not a Vaults - Get body. tenantId and
    vaultUri are set on every vault, so a body with neither is not one."""
    props = data.get("properties")
    if not isinstance(props, dict):
        return None
    if not (props.get("tenantId") or props.get("vaultUri")):
        return None
    return props


def evaluate(data, validation):
    props = vault_properties(data)
    if props is None:
        return respond(None, "the response is not a Key Vault resource: no properties.tenantId or vaultUri",
                       validation)
    value = props.get("enablePurgeProtection")
    if value is True:
        return respond(True, "enablePurgeProtection is true", validation, {"enablePurgeProtection": True})
    return respond(False, "Purge protection is not enabled (enablePurgeProtection is " + str(value) + ")",
                   validation, {"enablePurgeProtection": value}, ["Enable purge protection (irreversible)"])


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
