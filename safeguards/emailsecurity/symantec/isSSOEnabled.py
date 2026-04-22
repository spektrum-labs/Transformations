"""
Transformation: isSSOEnabled
Vendor: Symantec  |  Category: emailsecurity
Evaluates: Whether Single Sign-On (SSO/SAML) is configured and enabled in Symantec Email Security.cloud account settings.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isSSOEnabled", "vendor": "Symantec", "category": "emailsecurity"}
        }
    }


def is_truthy_value(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in ["true", "yes", "1", "enabled", "active", "configured", "on"]
    if isinstance(value, int):
        return value == 1
    return False


def evaluate(data):
    try:
        settings = data.get("settings", {})
        if not isinstance(settings, dict):
            settings = {}

        sso_keys = ["ssoEnabled", "sso_configured", "samlEnabled", "sso_enabled",
                    "saml_enabled", "ssoConfigured", "saml_configured", "singleSignOn",
                    "single_sign_on", "sso"]

        detected_key = ""
        detected_value = None
        enabled = False

        for key in sso_keys:
            if key in settings:
                detected_key = key
                detected_value = settings[key]
                enabled = is_truthy_value(detected_value)
                break

        if not detected_key:
            for k in settings:
                k_lower = str(k).lower()
                if "sso" in k_lower or "saml" in k_lower or "singlesign" in k_lower:
                    detected_key = k
                    detected_value = settings[k]
                    enabled = is_truthy_value(detected_value)
                    break

        return {
            "isSSOEnabled": enabled,
            "detectedSettingKey": detected_key,
            "detectedValue": str(detected_value) if detected_value is not None else "not found",
            "totalSettingsKeys": len(settings)
        }
    except Exception as e:
        return {"isSSOEnabled": False, "error": str(e)}


def transform(input):
    criteriaKey = "isSSOEnabled"
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
            pass_reasons.append("SSO/SAML is enabled and configured in account settings.")
            pass_reasons.append("Setting key: " + str(extra_fields.get("detectedSettingKey", "")) + " = " + str(extra_fields.get("detectedValue", "")))
        else:
            fail_reasons.append("SSO/SAML is not enabled or not configured in account settings.")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Configure Single Sign-On (SAML) in the Symantec Email Security.cloud portal to centralise identity management.")
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
