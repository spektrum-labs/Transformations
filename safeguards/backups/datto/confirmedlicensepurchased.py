"""
Transformation: confirmedLicensePurchased
Vendor: Datto BCDR
Category: Licensing

Evaluates if the license has been purchased for Datto BCDR.
"""

import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for _ in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None, api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {
                "status": "error" if (api_errors or []) else "success",
                "errors": api_errors or []
            },
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", [])
            },
            "transformation": {
                "status": "error" if (transformation_errors or []) else "success",
                "errors": transformation_errors or [],
                "inputSummary": input_summary or {}
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or []
            },
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "confirmedLicensePurchased",
                "vendor": "Datto",
                "category": "Licensing"
            }
        }
    }


ERROR_KEYS = ("error", "errors", "errorMessage", "errorType", "fault")
ASSET_KEYS = ("backups", "lastSnapshot", "agentVersion", "isPaused", "isArchived", "protectedVolumesCount",
              "lastScreenshotAttempt", "localSnapshots")


def error_text(obj):
    """A vendor or transport error carried by a dict, or None."""
    if not isinstance(obj, dict):
        return None
    for key in ERROR_KEYS:
        if obj.get(key):
            return str(key) + ": " + json.dumps(obj.get(key))[:200]
    code = obj.get("statusCode", obj.get("status_code", obj.get("code")))
    if isinstance(code, int) and not isinstance(code, bool) and code >= 400:
        return "HTTP " + str(code) + ": " + str(obj.get("message") or obj.get("detail") or "")[:200]
    return None


def looks_like_asset(obj):
    if not isinstance(obj, dict):
        return False
    for key in ASSET_KEYS:
        if key in obj:
            return True
    return False


def collect_assets(data):
    """Return (active_assets, device_count, None) for a readable Datto BCDR asset read, or (None, 0, problem).

    The e0d463e8 workflow calls GET /v1/bcdr/device, then GET /v1/bcdr/device/{serial}/asset per device,
    and hands over {"devices": [<asset list for device 1>, <asset list for device 2>, ...]}. A bare asset
    list, a single device's {"items": [...]} and a {"devices": [...]} of asset objects are read the same way.
    Anything that is not positive evidence of at least one protected asset is NOT a measurement: None, {},
    an error envelope, an empty device list or an empty asset list all return a problem, never an answer.
    """
    if data is None:
        return None, 0, "Datto returned no body; nothing was measured."
    problem = error_text(data)
    if problem:
        return None, 0, "Datto returned an error, so nothing was measured (" + problem + ")."
    if isinstance(data, dict):
        groups = data.get("devices")
        if groups is None:
            groups = data.get("items")
        if groups is None and looks_like_asset(data):
            groups = [data]
    elif isinstance(data, list):
        groups = data
    else:
        groups = None
    if not isinstance(groups, list):
        return None, 0, "Datto response has no device or asset list; nothing was measured."
    assets = []
    device_count = 0
    for group in groups:
        if isinstance(group, dict) and isinstance(group.get("items"), list):
            group = group.get("items")
        if isinstance(group, list):
            found = False
            for item in group:
                problem = error_text(item)
                if problem:
                    return None, 0, "Datto returned an error for a device, so the read is incomplete (" + problem + ")."
                if looks_like_asset(item):
                    assets.append(item)
                    found = True
            if found:
                device_count += 1
        elif isinstance(group, dict):
            problem = error_text(group)
            if problem:
                return None, 0, "Datto returned an error for a device, so the read is incomplete (" + problem + ")."
            if looks_like_asset(group):
                assets.append(group)
                device_count += 1
    if not assets:
        return None, 0, "Datto returned no protected assets (empty device or asset list); nothing was measured."
    active = [a for a in assets if a.get("isArchived") is not True]
    if not active:
        return None, device_count, "Every Datto asset returned is archived; there is no active asset to measure."
    return active, device_count, None


def percentage(part, whole):
    return round(100.0 * part / whole, 1) if whole else None


def not_measured(criteriaKey, validation, problem):
    return create_response(
        result={criteriaKey: None},
        validation=validation,
        fail_reasons=[problem],
        api_errors=[problem],
        input_summary={"measured": False},
    )


def load_input(input):
    if isinstance(input, bytes):
        input = input.decode("utf-8")
    if isinstance(input, str):
        input = json.loads(input)
    return extract_input(input)


def number(value):
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) else 0


def transform(input):
    criteriaKey = "confirmedLicensePurchased"
    try:
        data, validation = load_input(input)
        if validation.get("status") == "failed":
            return not_measured(criteriaKey, validation,
                                "Input validation failed: " + json.dumps(validation.get("errors"))[:200])
        assets, device_count, problem = collect_assets(data)
        if problem:
            return not_measured(criteriaKey, validation, problem)
        total = len(assets)
        licensed = device_count > 0
        pass_reasons = [str(device_count) + " Datto BCDR device(s) returned protected assets through the partner API, "
                        "which requires a registered device under service"]
        return create_response(
            result={criteriaKey: licensed},
            validation=validation, pass_reasons=pass_reasons,
            input_summary={"devicesWithAssets": device_count, "activeAssets": total},
        )

    except Exception as e:
        problem = "Transformation error: " + str(e)
        return create_response(
            result={criteriaKey: None},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[problem],
            api_errors=[problem],
        )
