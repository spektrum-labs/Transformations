"""
Transformation: keysHaveExpirationDate
Vendor: Microsoft Azure Key Vault  |  Category: Encryption

Criterion: every key has an expiration date (Azure Policy 152b15f7-8e1f-4c1f-ab71-8c010ba5dbc0).

Data source:
    getKeys -- GET https://{vaultName}.vault.azure.net/keys?api-version=7.4, token scope
    https://vault.azure.net/.default (https://learn.microsoft.com/en-us/rest/api/keyvault/keys/get-keys)

  keysHaveExpirationDate = true when the `value` list is present and every key has attributes.exp
  (an empty list is a vault with no keys, which the policy counts as compliant); false when any
  key has none. A body with no `value` list was never a key listing and is not evaluated.
  The data-plane list is paged (25 items a page by default). When the body still carries a
  nextLink, the unread pages could hold a non-compliant item, so an all-clear page is not
  evaluated; a non-compliant item on the page read is still a measured false.

Not evaluated (None, dataCollection status "error"): an ARM or Key Vault error envelope at the
top level or inside a response/result/apiResponse wrapper, a body of the wrong shape, or this
transform's own exception. An error is not a failed control, so it is never a measured False.
"""
import json
import ast
from datetime import datetime

KEY = "keysHaveExpirationDate"
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


def transform(input):
    try:
        data, error = unwrap(parse_input(input))
        if error:
            return not_measured("The Azure API returned an error: " + error)
        keys = data.get("value") if isinstance(data, dict) else None
        if not isinstance(keys, list):
            return not_measured("No `value` list in the Key Vault list-keys response, so the keys were never "
                                "listed")
        missing = 0
        for key in keys:
            if not isinstance(key, dict):
                return not_measured("Unexpected item in the Key Vault list-keys response")
            attributes = key.get("attributes")
            if not isinstance(attributes, dict) or attributes.get("exp") is None:
                missing = missing + 1
        summary = {"keyCount": len(keys), "keysWithoutExpiry": missing}
        if missing > 0:
            return measured(False, str(missing) + " of " + str(len(keys)) + " key(s) have no expiration date",
                            "Set an expiration date on every key", summary)
        if data.get("nextLink"):
            return not_measured("The key listing has further pages that were not read", summary)
        return measured(True, "All " + str(len(keys)) + " key(s) have an expiration date", None, summary)
    except Exception as e:
        return create_response(result={KEY: None}, transformation_errors=[str(e)],
                               api_errors=["Transformation error: " + str(e)],
                               fail_reasons=["Transformation error: " + str(e)])
