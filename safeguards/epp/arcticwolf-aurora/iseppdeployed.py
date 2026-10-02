"""isEPPDeployed for Arctic Wolf Aurora Endpoint Security (Aurora Protect).

Input: GET {baseURL}/devices/v2?page=1&page_size=200 (Get Devices Extended):
page_items[] with products[] {name, version, status}. Docs:
https://docs.arcticwolf.com/ja-jp/開発者およびoem/aurora-endpoint-defense-api/device-api/get-devices-extended

True when at least one device runs the Protect (prevention) agent.
"""

import json
from datetime import datetime

DOCS = "https://docs.arcticwolf.com/ja-jp/開発者およびoem/aurora-endpoint-defense-api/device-api/get-devices-extended"


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




def devices(body):
    """Get Devices Extended (GET /devices/v2): page_items, each with products, policy, state, background_detection."""
    if isinstance(body, dict):
        items = body.get("page_items")
        if isinstance(items, list):
            return [d for d in items if isinstance(d, dict)]
    if isinstance(body, list):
        return [d for d in body if isinstance(d, dict)]
    return None


def product_names(device):
    names = []
    for product in device.get("products") or []:
        if isinstance(product, dict) and isinstance(product.get("name"), str):
            names.append(product["name"].strip().lower())
    return names


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
    key = "isEPPDeployed"
    found = devices(unwrap(input))
    if found is None:
        return response(key, False, {}, fail_reasons=["No device list returned"], errors=["unreadable response"])
    protected = [d for d in found if any("protect" in n for n in product_names(d))]
    summary = {"devices": len(found), "protectDevices": len(protected)}
    if protected:
        return response(key, True, summary, pass_reasons=[f"Aurora Protect on {len(protected)} of {len(found)} device(s)"])
    return response(key, False, summary, fail_reasons=["No device reports the Aurora Protect agent"])
