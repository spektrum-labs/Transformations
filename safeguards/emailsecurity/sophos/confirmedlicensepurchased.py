"""
Transformation: confirmedLicensePurchased
Vendor: Sophos  |  Category: Email Security  |  Input: GET https://api.central.sophos.com/licenses/v1/licenses

Per-product licence for Sophos Email (5 Oct 2026). The shared Sophos licence file reads the account health check,
which does not say which product is licensed (TX #921), so Email Security read Not evaluated. The tenant licence
list does: each item carries product.code / product.name, type, perpetual, startDate and endDate.

- True: at least one Sophos Email licence (product code CEMA or CEMA-prefixed, or a product name starting
  "Sophos Email") is not a trial, has started, and is perpetual or ends today or later.
- False: the licence list was read and it carries no Sophos Email licence, or only expired, future or trial ones.
  Central Phish Threat (CPHISH) is a different product and never counts.
- Not evaluated (None, dataCollection error): an error body, no licenses array, an empty list (nothing to read),
  or a Sophos Email item whose dates cannot be read and no other item that is active.
"""
import json
from datetime import datetime

CRITERIA_KEY = "confirmedLicensePurchased"


def extract_input(input_data):
    if isinstance(input_data, (str, bytes)):
        input_data = json.loads(input_data.decode("utf-8") if isinstance(input_data, bytes) else input_data)
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    for _ in range(3):
        if not isinstance(data, dict):
            break
        nested = None
        for key in ("api_response", "response", "result", "apiResponse", "Output"):
            if isinstance(data.get(key), dict):
                nested = data[key]
                break
        if nested is None:
            break
        data = nested
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation, passed=(), failed=(), errors=(), summary=None):
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if errors else "success", "errors": list(errors)},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []),
                           "warnings": validation.get("warnings", [])},
            "transformation": {"status": "success", "errors": [], "inputSummary": summary or {}},
            "evaluation": {"passReasons": list(passed), "failReasons": list(failed) + list(errors),
                           "recommendations": [], "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0",
                         "transformationId": TRANSFORMATION_ID, "vendor": "Sophos", "category": CATEGORY},
        },
    }


def not_evaluated(reason, validation, summary=None):
    return create_response({CRITERIA_KEY: None}, validation, errors=[reason], summary=summary)


def day(value):
    """'YYYY-MM-DD' from an ISO date or timestamp string; '' when it is not one."""
    text = str(value or "").strip()[:10]
    if len(text) == 10 and text[4] == "-" and text[7] == "-" and (text[:4] + text[5:7] + text[8:]).isdigit():
        return text
    return ""


def licence_state(lic, today):
    """'active', 'expired', 'trial', 'future' or 'unknown' for one Sophos licence item."""
    if not isinstance(lic, dict):
        return "unknown"
    if str(lic.get("type") or "").strip().lower() == "trial":
        return "trial"
    start = day(lic.get("startDate"))
    if start and start > today:
        return "future"
    if lic.get("perpetual") is True:
        return "active"
    end = day(lic.get("endDate"))
    if not end:
        return "unknown"
    return "active" if end >= today else "expired"


def product_of(lic):
    product = lic.get("product") if isinstance(lic, dict) else None
    product = product if isinstance(product, dict) else {}
    return str(product.get("code") or "").strip(), str(product.get("name") or "").strip()

TRANSFORMATION_ID = "sophosEmailConfirmedLicensePurchased"
CATEGORY = "Email Security"
PRODUCT_LABEL = "Sophos Email"


def is_product(code, name):
    code = code.upper()
    if code == "CPHISH":
        return False
    return code == "CEMA" or code.startswith("CEMA") or name.lower().startswith("sophos email")


def transform(input):
    try:
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return not_evaluated("Input validation failed: the Sophos licence list was not read", validation)
        if not isinstance(data, dict) or "error" in data or "vendorErrorAsResponse" in data:
            return not_evaluated("Sophos did not return the licence list (error or unrecognised body)", validation)
        licences = data.get("licenses")
        if not isinstance(licences, list):
            return not_evaluated("The Sophos response carries no licenses array", validation)
        if not licences:
            return not_evaluated("The Sophos licence list is empty, so it proves nothing either way", validation)
        today = datetime.utcnow().date().isoformat()
        states = []
        for lic in licences:
            code, name = product_of(lic)
            if is_product(code, name):
                states.append((code or name[:40], licence_state(lic, today)))
        summary = {"licencesRead": len(licences), "productLicences": len(states),
                   "states": sorted(set(s for _, s in states))}
        result = {CRITERIA_KEY: None, "product": PRODUCT_LABEL, "productLicences": len(states)}
        active = [c for c, s in states if s == "active"]
        if active:
            result[CRITERIA_KEY] = True
            return create_response(result, validation, passed=[
                f"{PRODUCT_LABEL} licence is current (product {', '.join(sorted(set(active)))[:80]}, "
                f"{len(active)} active licence(s) in the tenant licence list)"], summary=summary)
        if any(s == "unknown" for _, s in states):
            return not_evaluated(f"A {PRODUCT_LABEL} licence is listed but its dates cannot be read", validation,
                                 summary=summary)
        result[CRITERIA_KEY] = False
        if states:
            why = f"every {PRODUCT_LABEL} licence is " + "/".join(sorted(set(s for _, s in states)))
        else:
            why = f"the tenant licence list ({len(licences)} item(s)) carries no {PRODUCT_LABEL} licence"
        return create_response(result, validation, failed=["No current " + PRODUCT_LABEL + " licence: " + why],
                               summary=summary)
    except Exception as e:
        return not_evaluated("Transformation error: " + str(e)[:200], {"status": "error", "errors": [], "warnings": []})
