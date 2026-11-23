# keysHaveExpirationDate.py
# Azure Key Vault - DP-6.3: Key Management - Key Expiration Dates
# Azure Policy: 152b15f7-8e1f-4c1f-ab71-8c010ba5dbc0
"""
keysHaveExpirationDate

Criterion: every key in the vault has an expiration date.

Data source: getKeys -- GET https://{vaultName}.vault.azure.net/keys?api-version=7.4, token scope
https://vault.azure.net/.default
(https://learn.microsoft.com/en-us/rest/api/keyvault/keys/get-keys/get-keys?view=rest-keyvault-keys-7.4).
Each KeyItem carries attributes.exp, "Expiry date in UTC" (unixtime). The list is paged: "If not
specified the service will return up to 25 results", with nextLink naming the next page, and the
definition sends no maxresults and does not follow nextLink.

  false = a key read has no attributes.exp (a definite failure, whatever the unread pages hold)
  true  = every key read has one, and there is no nextLink (the whole vault was read)
  None  = an empty vault (no keys: nothing to evaluate, not a pass), a further page unread
          with no failure on this one, no value list, an Azure error, or an exception

Every unmeasured path returns None, and respond() derives dataCollection.status from that value,
so an error body, an empty body or this file's own exception is Not evaluated, never a
measured false.
"""
import json
import ast
from datetime import datetime, timezone

KEY = "keysHaveExpirationDate"
VENDOR = "Microsoft Azure Key Vault"
CATEGORY = "Encryption"
METHOD = "getKeys"


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
    items, why = listing(data, "keys")
    if why:
        return respond(None, why, validation)
    missing = []
    for item in items:
        attributes = item.get("attributes")
        if not isinstance(attributes, dict) or attributes.get("exp") is None:
            missing.append(str(item.get("kid") or "?").split("/")[-1])
    extra = {"keysRead": len(items), "keysWithoutExpiration": len(missing)}
    if missing:
        return respond(False, str(len(missing)) + " of " + str(len(items)) + " key(s) read have no expiration "
                       "date: " + ", ".join(missing[:10]), validation, extra,
                       ["Set an expiration date on every Key Vault key"])
    if next_link(data):
        return respond(None, "All " + str(len(items)) + " key(s) on the first page have an expiration date, "
                       "but further pages were not read", validation, extra)
    if len(items) == 0:
        return respond(None, "The vault holds no keys, so there is no key expiration to evaluate",
                       validation, extra)
    return respond(True, "All " + str(len(items)) + " key(s) have an expiration date", validation, extra)


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
