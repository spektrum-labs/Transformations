"""confirmedLicensePurchased for Arctic Wolf Aurora Endpoint Defense (formerly Cylance Endpoint).

Input: GET {baseURL}/devices/v2/products ("Get device count", scope device:list). The vendor's page
documents three fields per row: name (the product), version (the product version) and count (the
number of devices on that product version). Page:
https://docs.arcticwolf.com/en/developer-and-oem/aurora-endpoint-defense-api/device-api/get-device-count

The page does not say whether the list is a bare array or sits inside the paging envelope other list
reads use (page_items), so both are read.

True only when at least one row has a device count above zero: a licensed product with endpoints on it.
An authenticated empty list is a tenant with nothing in use: False. A reply that is not a list, or whose
rows carry no numeric count, proves nothing and is reported as a data-collection error (Not evaluated).
"""

import json
from datetime import datetime

DOCS = "https://docs.arcticwolf.com/en/developer-and-oem/aurora-endpoint-defense-api/device-api/get-device-count"


def unwrap(value):
    """The engine hands the method's response in one of a few envelopes; peel them, never invent data."""
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return None
    if isinstance(value, bytes):
        try:
            value = json.loads(value.decode("utf-8"))
        except ValueError:
            return None
    if isinstance(value, dict) and "data" in value and "validation" in value:
        value = value.get("data")
    for unused in range(3):
        if isinstance(value, dict):
            for key in ("apiResponse", "api_response", "response", "result", "Output"):
                if key in value and isinstance(value.get(key), (dict, list)):
                    value = value[key]
                    break
            else:
                break
    return value


def rows_of(body):
    """The product rows, or None when the reply is not a list of them."""
    if isinstance(body, dict):
        body = body.get("page_items")
    if isinstance(body, list):
        return [r for r in body if isinstance(r, dict)]
    return None


def device_count(row):
    count = row.get("count")
    if isinstance(count, int) and not isinstance(count, bool):
        return count
    return None


def response(key, passed, summary, pass_reasons=None, fail_reasons=None, errors=None):
    return {
        "transformedResponse": {key: bool(passed)},
        "additionalInfo": {
            "dataCollection": {"status": "error" if errors else "success", "errors": errors or []},
            "validation": {"status": "passed" if not errors else "failed", "errors": [], "warnings": []},
            "transformation": {"status": "success", "errors": [], "inputSummary": summary},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                           "recommendations": [], "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0",
                         "transformationId": key, "vendor": "Arctic Wolf Aurora (Cylance)", "category": "Endpoint Security",
                         "source": DOCS},
        },
    }


def transform(input):
    key = "confirmedLicensePurchased"
    rows = rows_of(unwrap(input))
    if rows is None:
        return response(key, False, {}, fail_reasons=["No product list returned"], errors=["unreadable response"])
    counted = [(r, device_count(r)) for r in rows]
    measured = [pair for pair in counted if pair[1] is not None]
    if rows and not measured:
        return response(key, False, {"products": len(rows)}, fail_reasons=["No product row carries a device count"],
                        errors=["product rows have no numeric count"])
    in_use = [pair for pair in measured if pair[1] > 0]
    devices = sum(pair[1] for pair in in_use)
    summary = {"products": len(rows), "productsInUse": len(in_use), "devices": devices}
    if in_use:
        return response(key, True, summary,
                        pass_reasons=[f"{len(in_use)} Aurora product version(s) in use on {devices} device(s)"])
    return response(key, False, summary, fail_reasons=["No Aurora product is in use on any device"])
