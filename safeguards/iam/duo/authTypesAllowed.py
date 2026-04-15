"""
Transformation: authTypesAllowed
Vendor: Duo  |  Category: IAM
Evaluates: Inspects Duo account settings to determine which authentication factor types are
permitted. Evaluates push_enabled, sms_enabled, voice_enabled, mobile_otp_enabled,
hard_token_enabled, and u2f_enabled from the /admin/v1/settings response.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "authTypesAllowed", "vendor": "Duo", "category": "IAM"}
        }
    }


def evaluate(data):
    try:
        settings = {}
        if isinstance(data, dict):
            settings = data.get("settings", data)
        if not isinstance(settings, dict):
            settings = {}

        push_enabled = bool(settings.get("push_enabled", False))
        sms_enabled = bool(settings.get("sms_enabled", False))
        voice_enabled = bool(settings.get("voice_enabled", False))
        mobile_otp_enabled = bool(settings.get("mobile_otp_enabled", False))
        hard_token_enabled = bool(settings.get("hard_token_enabled", False))
        u2f_enabled = bool(settings.get("u2f_enabled", False))

        allowed_types = []
        if push_enabled:
            allowed_types.append("push")
        if sms_enabled:
            allowed_types.append("sms")
        if voice_enabled:
            allowed_types.append("voice")
        if mobile_otp_enabled:
            allowed_types.append("mobile_otp")
        if hard_token_enabled:
            allowed_types.append("hard_token")
        if u2f_enabled:
            allowed_types.append("u2f")

        has_auth_types = len(allowed_types) > 0

        return {
            "authTypesAllowed": allowed_types,
            "hasAuthTypesConfigured": has_auth_types,
            "pushEnabled": push_enabled,
            "smsEnabled": sms_enabled,
            "voiceEnabled": voice_enabled,
            "mobileOtpEnabled": mobile_otp_enabled,
            "hardTokenEnabled": hard_token_enabled,
            "u2fEnabled": u2f_enabled,
            "authTypeCount": len(allowed_types)
        }
    except Exception as e:
        return {"authTypesAllowed": [], "hasAuthTypesConfigured": False, "error": str(e)}


def transform(input):
    criteriaKey = "authTypesAllowed"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: [], "hasAuthTypesConfigured": False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )
        eval_result = evaluate(data)
        allowed_types = eval_result.get(criteriaKey, [])
        has_auth_types = eval_result.get("hasAuthTypesConfigured", False)
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if has_auth_types:
            pass_reasons.append(str(len(allowed_types)) + " authentication type(s) configured: " + ", ".join(allowed_types))
        else:
            fail_reasons.append("No authentication factor types are enabled in Duo account settings")
            recommendations.append("Enable at least one strong authentication factor type such as push, hard_token, or u2f in Duo account settings")
        return create_response(
            result=eval_result,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"authTypeCount": eval_result.get("authTypeCount", 0), "authTypesAllowed": allowed_types}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: [], "hasAuthTypesConfigured": False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
