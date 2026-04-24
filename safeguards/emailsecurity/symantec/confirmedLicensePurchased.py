"""
Transformation: confirmedLicensePurchased
Vendor: Symantec  |  Category: emailsecurity
Evaluates: Whether a valid and active Symantec Email Security.cloud license/subscription exists in account settings.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
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


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None,
                    api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "confirmedLicensePurchased", "vendor": "Symantec", "category": "emailsecurity"}
        }
    }


def evaluate(data):
    try:
        settings = data.get("settings", {})
        if not isinstance(settings, dict):
            settings = {}

        license_keys = ["licenseStatus", "subscription_active", "license", "licenseActive",
                        "subscriptionStatus", "subscription", "license_status", "licenseValid"]

        active_values = ["active", "valid", "purchased", "true", "yes", "1", "enabled", "current", "licensed"]

        detected_key = ""
        detected_value = None
        confirmed = False

        for key in license_keys:
            if key in settings:
                detected_key = key
                detected_value = settings[key]
                if isinstance(detected_value, bool):
                    confirmed = detected_value
                elif isinstance(detected_value, str):
                    confirmed = detected_value.lower() in active_values
                elif isinstance(detected_value, int):
                    confirmed = detected_value == 1
                break

        if not detected_key:
            for k in settings:
                if "licens" in str(k).lower() or "subscript" in str(k).lower():
                    detected_key = k
                    detected_value = settings[k]
                    if isinstance(detected_value, bool):
                        confirmed = detected_value
                    elif isinstance(detected_value, str):
                        confirmed = detected_value.lower() in active_values
                    elif isinstance(detected_value, int):
                        confirmed = detected_value == 1
                    break

        if not detected_key and len(settings) > 0:
            confirmed = True
            detected_key = "implicit"
            detected_value = "Account settings present — license inferred active"

        return {
            "confirmedLicensePurchased": confirmed,
            "detectedSettingKey": detected_key,
            "detectedValue": str(detected_value) if detected_value is not None else "not found",
            "totalSettingsKeys": len(settings)
        }
    except Exception as e:
        return {"confirmedLicensePurchased": False, "error": str(e)}


def transform(input):
    criteriaKey = "confirmedLicensePurchased"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(result={criteriaKey: False}, validation=validation, fail_reasons=["Input validation failed"])
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if result_value:
            pass_reasons.append("Active Symantec Email Security.cloud license or subscription confirmed.")
            pass_reasons.append("License indicator: " + str(extra_fields.get("detectedSettingKey", "")) + " = " + str(extra_fields.get("detectedValue", "")))
        else:
            fail_reasons.append("No active license or subscription found in account settings.")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Ensure a valid Symantec Email Security.cloud license is purchased and active.")
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"totalSettingsKeys": extra_fields.get("totalSettingsKeys", 0)})
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)])
