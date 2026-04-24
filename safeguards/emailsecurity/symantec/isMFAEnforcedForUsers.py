"""
Transformation: isMFAEnforcedForUsers
Vendor: Symantec  |  Category: emailsecurity
Evaluates: Whether Multi-Factor Authentication (MFA) is enforced for users accessing the Symantec Email Security.cloud portal.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isMFAEnforcedForUsers", "vendor": "Symantec", "category": "emailsecurity"}
        }
    }


def is_truthy_value(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in ["true", "yes", "1", "enabled", "active", "enforced", "required", "on"]
    if isinstance(value, int):
        return value == 1
    return False


def evaluate(data):
    try:
        settings = data.get("settings", {})
        if not isinstance(settings, dict):
            settings = {}

        mfa_keys = ["mfaEnforced", "mfa_required", "twoFactorAuth", "mfa_enforced",
                    "twoFactor", "two_factor_auth", "two_factor_enabled", "mfaEnabled",
                    "mfa_enabled", "multiFactorAuth", "multi_factor_auth", "mfa"]

        detected_key = ""
        detected_value = None
        enforced = False

        for key in mfa_keys:
            if key in settings:
                detected_key = key
                detected_value = settings[key]
                enforced = is_truthy_value(detected_value)
                break

        if not detected_key:
            for k in settings:
                k_lower = str(k).lower()
                if "mfa" in k_lower or "twofactor" in k_lower or "two_factor" in k_lower or "multifactor" in k_lower:
                    detected_key = k
                    detected_value = settings[k]
                    enforced = is_truthy_value(detected_value)
                    break

        return {
            "isMFAEnforcedForUsers": enforced,
            "detectedSettingKey": detected_key,
            "detectedValue": str(detected_value) if detected_value is not None else "not found",
            "totalSettingsKeys": len(settings)
        }
    except Exception as e:
        return {"isMFAEnforcedForUsers": False, "error": str(e)}


def transform(input):
    criteriaKey = "isMFAEnforcedForUsers"
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
            pass_reasons.append("MFA is enforced for users accessing the Symantec Email Security.cloud portal.")
            pass_reasons.append("Setting key: " + str(extra_fields.get("detectedSettingKey", "")) + " = " + str(extra_fields.get("detectedValue", "")))
        else:
            fail_reasons.append("MFA is not enforced or not configured in account settings.")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Enable and enforce Multi-Factor Authentication for all users in the Symantec Email Security.cloud portal.")
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
