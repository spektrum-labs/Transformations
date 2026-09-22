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


def transform(input):
    criteriaKey = "confirmedLicensePurchased"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        # Default to True if data is present
        # `data is not None` asked whether a RESPONSE ARRIVED, not what it said, so any
        # 2xx body -- including one describing the control as OFF -- satisfied this
        # criterion and no input could make it false. Resolved from the payload now.
        default_value = _affirmative_signal(data)

        license_purchased = data.get('licensePurchased', default_value) if isinstance(data, dict) else default_value

        device_count = 0
        if not license_purchased and isinstance(data, dict):
            # Check if there are any devices (indicates active subscription)
            devices = (
                data.get("items", []) or
                data.get("devices", []) or
                data.get("agents", []) or
                data.get("data", {}).get("rows", [])
            )
            device_count = len(devices)
            if device_count > 0:
                license_purchased = True

            # Check totalRecords
            if 'totalRecords' in data and data['totalRecords'] > 0:
                license_purchased = True

        if license_purchased:
            pass_reasons.append("Datto BCDR license purchase confirmed")
            if device_count > 0:
                pass_reasons.append(f"{device_count} devices registered (indicates active subscription)")
        else:
            fail_reasons.append("Datto BCDR license purchase not confirmed")
            recommendations.append("Confirm Datto BCDR license has been purchased")

        return create_response(
            result={criteriaKey: license_purchased},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "licensePurchased": license_purchased,
                "deviceCount": device_count
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )


def _affirmative_signal(data):
    """True only when the payload POSITIVELY evidences the control.

    Replaces `data is not None`, which asked whether a response arrived rather than what
    it said -- so any 2xx body, including one describing the control as OFF, satisfied the
    criterion and no input could ever make it false. Measured 2026-09-21.

    Deliberately conservative, in this order:
      * an unreadable, empty or error body           -> False
      * an explicit OFF among the recognised keys    -> False   (beats any other signal)
      * an explicit ON among the recognised keys     -> True
      * a non-empty population of records/settings   -> True
      * anything unrecognised                        -> False  (never True by default)
    """
    if not isinstance(data, dict) or not data:
        return False
    for key in ("error", "errors", "errorMessage", "errorType", "fault", "PSError"):
        if data.get(key):
            return False
    on_keys = ("enabled", "isEnabled", "active", "isActive", "configured", "isConfigured",
               "enforced", "isEnforced", "loggingEnabled", "status", "state", "licensed",
               "licensePurchased", "subscribed", "subscription")
    present = [data[k] for k in on_keys if k in data]
    off_words = ("false", "disabled", "off", "inactive", "none", "expired", "cancelled")
    on_words = ("true", "enabled", "on", "active", "success", "ok", "valid", "licensed")
    for value in present:
        if value is False:
            return False
        if isinstance(value, str) and value.strip().lower() in off_words:
            return False
    for value in present:
        if value is True:
            return True
        if isinstance(value, str) and value.strip().lower() in on_words:
            return True
        if isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0:
            return True
    for key in ("items", "data", "records", "results", "logs", "events", "policies",
                "settings", "configurations", "devices", "agents", "users", "licenses"):
        value = data.get(key)
        if isinstance(value, list) and value:
            return True
        if isinstance(value, dict) and value:
            return True
    return False
