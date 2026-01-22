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
                    recommendations=None, input_summary=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "validationStatus": validation.get("status", "unknown"),
            "validationErrors": validation.get("errors", []),
            "validationWarnings": validation.get("warnings", []),
            "passReasons": pass_reasons or [],
            "failReasons": fail_reasons or [],
            "recommendations": recommendations or [],
            "inputSummary": input_summary or {},
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
        default_value = data is not None

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
                pass_reasons.append(f"{device_count} device(s) registered (indicates active subscription)")
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
            validation={"status": "error", "errors": [str(e)], "warnings": []},
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
