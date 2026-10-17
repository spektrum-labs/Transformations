# isManagedIdentityUsed.py
# Azure Key Vault - IM-3.1: Application Identity Security - Managed Identities
"""
isManagedIdentityUsed

Criterion: applications reach the vault with managed identities.

Data source: getRoleAssignments -- GET https://management.azure.com/subscriptions/{subscriptionId}
/resourceGroups/{resourceGroupName}/providers/Microsoft.KeyVault/vaults/{vaultName}/providers
/Microsoft.Authorization/roleAssignments?api-version=2022-04-01
(https://learn.microsoft.com/en-us/rest/api/authorization/role-assignments/list-for-resource?view=rest-authorization-2022-04-01).
The RTA row must name this method; it used to name getVaultProperties, whose body carries no
role assignments, so the old code fell through to an unconditional `return True` on every RBAC
vault.

NOT MEASURED from this response, and the reason is in the vendor's schema: properties.principalType
is the enum User | Group | ServicePrincipal | ForeignGroup | Device | AgentUser |
AgentServicePrincipal. A managed identity is reported as ServicePrincipal, the same value as an
app registration holding a client secret, so "managed" cannot be read from it. Nor can an absence
be read as a failure: a vault on access policies (enableRbacAuthorization false) grants data
access outside Azure RBAC entirely. Every path therefore returns None with dataCollection.status
"error" (Not evaluated), with the service-principal assignment count as evidence. A real
measurement needs the principal ids cross-referenced against managed identities (Azure Resource
Graph identity.principalId, or Microsoft Graph servicePrincipalType).

Every unmeasured path returns None, and respond() derives dataCollection.status from that value,
so an error body, an empty body or this file's own exception is Not evaluated, never a
measured false.
"""
import json
import ast
from datetime import datetime, timezone

KEY = "isManagedIdentityUsed"
VENDOR = "Microsoft Azure Key Vault"
CATEGORY = "Encryption"
METHOD = "getRoleAssignments"


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


def listing(data, what):
    """(items, None) or (None, reason). A list response is {"value": [...], "nextLink": ...};
    only an explicit value list proves the listing ran."""
    items = data.get("value")
    if not isinstance(items, list):
        return None, "no value list in the response: the " + what + " were never listed"
    for item in items:
        if not isinstance(item, dict):
            return None, "an entry in the " + what + " list is not an object"
    return items, None


def next_link(data):
    link = data.get("nextLink") or data.get("@odata.nextLink")
    return link if isinstance(link, str) and link.strip() else None


def evaluate(data, validation):
    items, why = listing(data, "role assignments")
    if why:
        return respond(None, why, validation)
    if next_link(data):
        return respond(None, "Only the first page of role assignments was read", validation)
    counts = {}
    for item in items:
        props = item.get("properties")
        kind = props.get("principalType") if isinstance(props, dict) else None
        kind = str(kind or "unknown")
        counts[kind] = counts.get(kind, 0) + 1
    sp = counts.get("ServicePrincipal", 0) + counts.get("AgentServicePrincipal", 0)
    extra = {"roleAssignmentCount": len(items), "servicePrincipalAssignmentCount": sp}
    if sp == 0:
        return respond(None, "Not measured: no service principal holds an Azure role on this vault, but a vault "
                       "on access policies grants data access outside Azure RBAC, so this does not show that no "
                       "managed identity is used", validation, extra)
    return respond(None, "Not measured: " + str(sp) + " service principal role assignment(s) apply to this "
                   "vault, and Azure reports managed identities and app registrations alike as "
                   "ServicePrincipal, so whether any is a managed identity cannot be read here",
                   validation, extra)


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
