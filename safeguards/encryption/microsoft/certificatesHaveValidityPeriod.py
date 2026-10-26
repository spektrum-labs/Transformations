"""
Transformation: certificatesHaveValidityPeriod
Vendor: Microsoft Azure Key Vault  |  Category: Encryption

Criterion: every certificate is valid for at most 397 days (Azure Policy 0a075868-4c26-42ef-914c-5bc007359560).

Data source:
    getCertificates -- GET https://{vaultName}.vault.azure.net/certificates?api-version=7.4, token
    scope https://vault.azure.net/.default
    (https://learn.microsoft.com/en-us/rest/api/keyvault/certificates/get-certificates)

  certificatesHaveValidityPeriod = true when the `value` list is present and every certificate's
  attributes.exp - attributes.nbf is at most 397 days (an empty list is a vault with no
  certificates, which the policy counts as compliant); false when any certificate exceeds it or
  lacks nbf/exp. A body with no `value` list was never a certificate listing and is not evaluated.
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

KEY = "certificatesHaveValidityPeriod"
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

MAX_VALIDITY_DAYS = 397  # CA/Browser Forum baseline requirement
SECONDS_PER_DAY = 86400


def transform(input):
    try:
        data, error = unwrap(parse_input(input))
        if error:
            return not_measured("The Azure API returned an error: " + error)
        certificates = data.get("value") if isinstance(data, dict) else None
        if not isinstance(certificates, list):
            return not_measured("No `value` list in the Key Vault list-certificates response, so the "
                                "certificates were never listed")
        too_long = 0
        for cert in certificates:
            if not isinstance(cert, dict):
                return not_measured("Unexpected item in the Key Vault list-certificates response")
            attributes = cert.get("attributes")
            nbf = attributes.get("nbf") if isinstance(attributes, dict) else None
            exp = attributes.get("exp") if isinstance(attributes, dict) else None
            if nbf is None or exp is None or (exp - nbf) / SECONDS_PER_DAY > MAX_VALIDITY_DAYS:
                too_long = too_long + 1
        summary = {"certificateCount": len(certificates), "certificatesOverMaxValidity": too_long}
        if too_long > 0:
            return measured(False, str(too_long) + " of " + str(len(certificates)) + " certificate(s) have no "
                            "validity period or one longer than " + str(MAX_VALIDITY_DAYS) + " days",
                            "Reissue those certificates with a validity period of at most "
                            + str(MAX_VALIDITY_DAYS) + " days", summary)
        if data.get("nextLink"):
            return not_measured("The certificate listing has further pages that were not read", summary)
        return measured(True, "All " + str(len(certificates)) + " certificate(s) are valid for at most "
                        + str(MAX_VALIDITY_DAYS) + " days", None, summary)
    except Exception as e:
        return create_response(result={KEY: None}, transformation_errors=[str(e)],
                               api_errors=["Transformation error: " + str(e)],
                               fail_reasons=["Transformation error: " + str(e)])
