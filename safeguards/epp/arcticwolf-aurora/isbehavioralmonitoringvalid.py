"""isBehavioralMonitoringValid for Arctic Wolf Aurora Endpoint Security.

Input: GET {baseURL}/devices/v2?page=1&page_size=200 (Get Devices Extended):
page_items[] with background_detection (background threat detection status). Docs:
https://docs.arcticwolf.com/ja-jp/開発者およびoem/aurora-endpoint-defense-api/device-api/get-devices-extended

True when there is at least one device and background detection is on for every
device that reports the field; a device that does not report it fails the check.
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
    key = "isBehavioralMonitoringValid"
    found = devices(unwrap(input))
    if not found:
        return response(key, False, {"devices": 0}, fail_reasons=["No devices returned"],
                        errors=[] if found == [] else ["unreadable response"])
    on = [d for d in found if d.get("background_detection") is True]
    summary = {"devices": len(found), "backgroundDetectionOn": len(on)}
    if len(on) == len(found):
        return response(key, True, summary, pass_reasons=[f"Background threat detection on for all {len(found)} device(s)"])
    return response(key, False, summary, fail_reasons=[f"Background threat detection off or unreported on {len(found) - len(on)} device(s)"])
