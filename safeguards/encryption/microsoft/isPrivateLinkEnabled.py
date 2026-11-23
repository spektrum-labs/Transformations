"""
Transformation: isPrivateLinkEnabled
Vendor: Microsoft Azure Key Vault  |  Category: Encryption

Criterion: at least one private endpoint connection to the vault is approved.

Data source:
    getPrivateEndpointConnections -- GET https://management.azure.com/subscriptions/{subscriptionId}/
    resourceGroups/{resourceGroupName}/providers/Microsoft.KeyVault/vaults/{vaultName}/
    privateEndpointConnections?api-version=2023-07-01, a {"value": [...]} list. A Vaults - Get body
    is also read, from properties.privateEndpointConnections.

  isPrivateLinkEnabled = true when any connection has
  properties.privateLinkServiceConnectionState.status "Approved"; false when the listed
  connections (possibly none) include no approved one.

Not evaluated (None, dataCollection status "error"): an ARM or Key Vault error envelope at the
top level or inside a response/result/apiResponse wrapper, a body of the wrong shape, or this
transform's own exception. An error is not a failed control, so it is never a measured False.
"""
import json
import ast
from datetime import datetime

KEY = "isPrivateLinkEnabled"
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
        if isinstance(data, list):
            connections = data
        elif isinstance(data, dict) and isinstance(data.get("value"), list):
            connections = data["value"]
        elif vault_properties(data) is not None:
            connections = vault_properties(data).get("privateEndpointConnections") or []
        else:
            return not_measured("No private endpoint connection list in the response, so the connections "
                                "were never listed")
        if not isinstance(connections, list):
            return not_measured("privateEndpointConnections is not a list")
        approved = 0
        for conn in connections:
            props = conn.get("properties") if isinstance(conn, dict) else None
            state = props.get("privateLinkServiceConnectionState") if isinstance(props, dict) else None
            if isinstance(state, dict) and state.get("status") == "Approved":
                approved = approved + 1
        summary = {"connectionCount": len(connections), "approvedCount": approved}
        if approved > 0:
            return measured(True, str(approved) + " of " + str(len(connections))
                            + " private endpoint connection(s) approved", None, summary)
        return measured(False, "No approved private endpoint connection among " + str(len(connections)),
                        "Create a private endpoint for the vault and approve its connection", summary)
    except Exception as e:
        return create_response(result={KEY: None}, transformation_errors=[str(e)],
                               api_errors=["Transformation error: " + str(e)],
                               fail_reasons=["Transformation error: " + str(e)])
