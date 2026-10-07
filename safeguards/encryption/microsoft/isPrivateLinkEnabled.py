# isPrivateLinkEnabled.py
# Azure Key Vault - NS-2.1: Cloud Service Security - Azure Private Link
"""
isPrivateLinkEnabled

Criterion: at least one private endpoint connection to the vault is approved.

Data source: getPrivateEndpointConnections -- GET https://management.azure.com/subscriptions
/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.KeyVault/vaults/{vaultName}
/privateEndpointConnections?api-version=2023-07-01
(https://learn.microsoft.com/en-us/rest/api/keyvault/keyvault/private-endpoint-connections/list-by-resource?view=rest-keyvault-keyvault-2023-07-01).
Each connection's properties.privateLinkServiceConnectionState.status is the enum Pending |
Approved | Rejected | Disconnected. The definition follows nextLink. A Vaults - Get body is also
accepted, reading properties.privateEndpointConnections.

  true  = some connection's status is "Approved"
  false = the listing ran and none is (including no connections: a proven empty set)
  None  = a further page unread with none approved so far, no connection list, an Azure error,
          or an exception

Every unmeasured path returns None, and respond() derives dataCollection.status from that value,
so an error body, an empty body or this file's own exception is Not evaluated, never a
measured false.
"""
import json
import ast
from datetime import datetime, timezone

KEY = "isPrivateLinkEnabled"
VENDOR = "Microsoft Azure Key Vault"
CATEGORY = "Encryption"
METHOD = "getPrivateEndpointConnections"


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
    items = data.get("value")
    if items is None and isinstance(data.get("properties"), dict):
        items = data["properties"].get("privateEndpointConnections")
        if items is None and data["properties"].get("tenantId"):
            items = []
    if not isinstance(items, list):
        return respond(None, "no private endpoint connection list in the response: the connections were "
                       "never listed", validation)
    states = []
    for item in items:
        props = item.get("properties") if isinstance(item, dict) else None
        state = props.get("privateLinkServiceConnectionState") if isinstance(props, dict) else None
        status = state.get("status") if isinstance(state, dict) else None
        states.append(str(status))
        if status == "Approved":
            return respond(True, "An approved private endpoint connection exists", validation,
                           {"privateEndpointConnectionCount": len(items)})
    extra = {"privateEndpointConnectionCount": len(items), "connectionStates": states[:20]}
    if next_link(data):
        return respond(None, "No approved connection on the first page, and further pages were not read",
                       validation, extra)
    return respond(False, str(len(items)) + " private endpoint connection(s); none is Approved", validation,
                   extra, ["Create and approve a private endpoint for the vault"])


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
