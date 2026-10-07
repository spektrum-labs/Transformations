# certificatesHaveValidityPeriod.py
# Azure Key Vault - DP-7.1: Certificate Management - Maximum Validity Period
# Azure Policy: 0a075868-4c26-42ef-914c-5bc007359560
"""
certificatesHaveValidityPeriod

Criterion: no certificate in the vault is valid for more than 397 days.

Data source: getCertificates -- GET https://{vaultName}.vault.azure.net/certificates?api-version=7.4,
token scope https://vault.azure.net/.default
(https://learn.microsoft.com/en-us/rest/api/keyvault/certificates/get-certificates/get-certificates?view=rest-keyvault-certificates-7.4).
Each CertificateItem carries attributes.nbf ("Not before date in UTC") and attributes.exp ("Expiry
date in UTC"), both unixtime. The list is paged at up to 25 by default with nextLink, which the
definition does not follow.

  false = a certificate read is valid for more than 397 days (definite, whatever is unread)
  true  = every certificate read has nbf and exp within 397 days, and there is no nextLink
  None  = an empty vault (no certificates: nothing to evaluate, not a pass), a certificate whose
          validity cannot be read, a further page unread, no value list, an Azure error, or an
          exception

Every unmeasured path returns None, and respond() derives dataCollection.status from that value,
so an error body, an empty body or this file's own exception is Not evaluated, never a
measured false.
"""
import json
import ast
from datetime import datetime, timezone

KEY = "certificatesHaveValidityPeriod"
VENDOR = "Microsoft Azure Key Vault"
CATEGORY = "Encryption"
METHOD = "getCertificates"


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
MAX_VALIDITY_DAYS = 397  # CA/Browser Forum maximum for publicly trusted TLS certificates
SECONDS_PER_DAY = 86400



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
    items, why = listing(data, "certificates")
    if why:
        return respond(None, why, validation)
    too_long = []
    unreadable = []
    for item in items:
        name = str(item.get("id") or "?").split("/")[-1]
        attributes = item.get("attributes")
        nbf = attributes.get("nbf") if isinstance(attributes, dict) else None
        exp = attributes.get("exp") if isinstance(attributes, dict) else None
        if isinstance(nbf, bool) or isinstance(exp, bool) or not isinstance(nbf, (int, float)) \
                or not isinstance(exp, (int, float)):
            unreadable.append(name)
            continue
        if (exp - nbf) / SECONDS_PER_DAY > MAX_VALIDITY_DAYS:
            too_long.append(name + " (" + str(int((exp - nbf) / SECONDS_PER_DAY)) + " days)")
    extra = {"certificatesRead": len(items), "certificatesOverMaximum": len(too_long),
             "maxValidityDays": MAX_VALIDITY_DAYS}
    if too_long:
        return respond(False, str(len(too_long)) + " of " + str(len(items)) + " certificate(s) read are valid "
                       "for more than " + str(MAX_VALIDITY_DAYS) + " days: " + ", ".join(too_long[:10]),
                       validation, extra, ["Reissue certificates with a validity period of at most 397 days"])
    if unreadable:
        return respond(None, "The validity period of " + str(len(unreadable)) + " certificate(s) cannot be read "
                       "(no numeric nbf/exp): " + ", ".join(unreadable[:10]), validation, extra)
    if next_link(data):
        return respond(None, "All " + str(len(items)) + " certificate(s) on the first page are within "
                       + str(MAX_VALIDITY_DAYS) + " days, but further pages were not read", validation, extra)
    if len(items) == 0:
        return respond(None, "The vault holds no certificates, so there is no validity period to evaluate",
                       validation, extra)
    return respond(True, "All " + str(len(items)) + " certificate(s) are valid for at most "
                   + str(MAX_VALIDITY_DAYS) + " days", validation, extra)


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
