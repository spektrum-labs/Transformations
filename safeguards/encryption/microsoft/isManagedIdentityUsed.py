"""
Transformation: isManagedIdentityUsed
Vendor: Microsoft Azure Key Vault  |  Category: Encryption

Criterion: applications reach the vault with managed identities (MCSB IM-3).

Data source (as wired):
    getVaultProperties -- GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/
    {resourceGroupName}/providers/Microsoft.KeyVault/vaults/{vaultName}?api-version=2023-07-01
    (https://learn.microsoft.com/en-us/rest/api/keyvault/keyvault/vaults/get)

THIS BODY CANNOT ANSWER THE CRITERION, so the transform never returns true or false from it. The
Microsoft.KeyVault/vaults resource has no `identity` block (a vault does not hold an identity; the
callers do). Access policies name a principal by objectId only, with nothing saying whether it is a
managed identity, a user or an app registration, and an RBAC vault lists no principals at all. The
previous rule returned true for every RBAC vault and for any vault with an access policy, which is
a pass from a body that shows nothing about managed identities.

Every input therefore returns isManagedIdentityUsed = None with dataCollection status "error" (not
evaluated). Answering it needs role-assignment data scoped to the vault
(Microsoft.Authorization/roleAssignments) resolved to service principals whose
servicePrincipalType is "ManagedIdentity"; that is an integration change, not a transformation one.
"""
import json
import ast
from datetime import datetime

KEY = "isManagedIdentityUsed"
VENDOR = "Microsoft Azure Key Vault"
CATEGORY = "Encryption"

WRAPPER_KEYS = ["api_response", "response", "result", "apiResponse", "Output", "rawResponse", "data"]


def parse_input(input):
    if isinstance(input, bytes):
        input = input.decode("utf-8")
    if isinstance(input, str):
        text = input.strip()
        if not text:
            return None
        try:
            return json.loads(text)
        except ValueError:
            return ast.literal_eval(text)
    return input


def error_message(body):
    """The error an ARM or Key Vault error envelope carries, or None for any other body."""
    if not isinstance(body, dict):
        return None
    error = body.get("error") or body.get("errors")
    if isinstance(error, dict):
        parts = [str(error.get(name)) for name in ("code", "message") if error.get(name)]
        return (": ".join(parts) or "error")[:300]
    if isinstance(error, str):
        return error[:300]
    if error:
        return str(body.get("errorType") or body.get("message") or "error")[:300]
    status = body.get("statusCode") or body.get("status_code") or body.get("status")
    if isinstance(status, str) and status.strip().isdigit():
        status = int(status.strip())
    if isinstance(status, int) and not isinstance(status, bool) and status >= 400:
        return ("HTTP " + str(status) + " " + str(body.get("message") or "")).strip()
    return None


def unwrap(data):
    """Peel the integration's wrappers. Returns (body, error); an error at any level wins."""
    for i in range(5):
        message = error_message(data)
        if message:
            return data, message
        if not isinstance(data, dict):
            return data, None
        inner = None
        for name in WRAPPER_KEYS:
            if isinstance(data.get(name), dict):
                inner = data[name]
                break
        if inner is None:
            return data, None
        data = inner
    return data, error_message(data)


def create_response(result, pass_reasons=None, fail_reasons=None, recommendations=None,
                    input_summary=None, api_errors=None, transformation_errors=None):
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": "unknown", "errors": [], "warnings": []},
            "transformation": {"status": "error" if (transformation_errors or []) else "success",
                               "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                           "recommendations": recommendations or [], "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "2.0",
                         "transformationId": KEY, "vendor": VENDOR, "category": CATEGORY},
        },
    }


def not_measured(reason, input_summary=None):
    return create_response(result={KEY: None}, api_errors=[reason], fail_reasons=[reason],
                           input_summary=input_summary)


def measured(passed, line, recommendation, input_summary=None):
    if passed:
        return create_response(result={KEY: True}, pass_reasons=[line], input_summary=input_summary)
    return create_response(result={KEY: False}, fail_reasons=[line], recommendations=[recommendation],
                           input_summary=input_summary)


def vault_properties(data):
    """properties of a Vaults - Get body, or None when the body is not one."""
    if not isinstance(data, dict):
        return None
    properties = data.get("properties")
    return properties if isinstance(properties, dict) else None


def network_acls(properties):
    acls = properties.get("networkAcls")
    return acls if isinstance(acls, dict) else {}


def transform(input):
    try:
        data, error = unwrap(parse_input(input))
        if error:
            return not_measured("The Azure API returned an error: " + error)
        properties = vault_properties(data)
        if properties is None:
            return not_measured("No Key Vault resource properties in the response, so the vault was never read")
        policies = properties.get("accessPolicies")
        summary = {"enableRbacAuthorization": properties.get("enableRbacAuthorization"),
                   "accessPolicyCount": len(policies) if isinstance(policies, list) else None}
        return not_measured("A Key Vault resource body cannot show managed-identity use: it has no identity "
                            "block, access policies do not say what kind of principal they name, and RBAC "
                            "vaults list no principals. Needs role-assignment data resolved to managed "
                            "identities.", summary)
    except Exception as e:
        return create_response(result={KEY: None}, transformation_errors=[str(e)],
                               api_errors=["Transformation error: " + str(e)],
                               fail_reasons=["Transformation error: " + str(e)])
