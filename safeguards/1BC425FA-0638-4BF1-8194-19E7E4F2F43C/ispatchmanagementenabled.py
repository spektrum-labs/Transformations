"""
Transformation: isPatchManagementEnabled
Vendor: MDR / Managed Detection and Response
Category: Endpoint Security / Patch Management

Evaluates if patch management is enabled and valid.
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
                    recommendations=None, input_summary=None, transformation_errors=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "validationStatus": validation.get("status", "unknown"),
            "validationErrors": validation.get("errors", []),
            "validationWarnings": validation.get("warnings", []),
            "transformationErrors": transformation_errors or [],
            "passReasons": pass_reasons or [],

            "failReasons": fail_reasons or [],
            "recommendations": recommendations or [],
            "inputSummary": input_summary or {},
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "isPatchManagementEnabled",
                "vendor": "MDR Provider",
                "category": "Endpoint Security"
            }
        }
    }


def transform(input):
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={"isPatchManagementEnabled": False, "isPatchManagementValid": False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        # Default to True if data is present (indicates active integration)
        default_value = data is not None

        is_patch_management_enabled = False
        is_patch_management_valid = False

        if isinstance(data, dict):
            is_patch_management_enabled = data.get('isPatchManagementEnabled', default_value)
            is_patch_management_valid = data.get('isPatchManagementValid', default_value)
        else:
            is_patch_management_enabled = default_value
            is_patch_management_valid = default_value

        if is_patch_management_enabled:
            pass_reasons.append("Patch management is enabled")
        else:
            fail_reasons.append("Patch management is not enabled")
            recommendations.append("Enable patch management for endpoint security")

        if is_patch_management_valid:
            pass_reasons.append("Patch management configuration is valid")
        else:
            if is_patch_management_enabled:
                fail_reasons.append("Patch management configuration is not valid")
                recommendations.append("Review and correct patch management configuration")

        return create_response(
            result={
                "isPatchManagementEnabled": is_patch_management_enabled,
                "isPatchManagementValid": is_patch_management_valid
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "patchManagementEnabled": is_patch_management_enabled,
                "patchManagementValid": is_patch_management_valid
            }
        )

    except Exception as e:
        return create_response(
            result={"isPatchManagementEnabled": False, "isPatchManagementValid": False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
