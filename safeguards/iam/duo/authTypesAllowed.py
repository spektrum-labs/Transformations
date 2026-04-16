"""
Transformation: authTypesAllowed
Vendor: Duo  |  Category: iam
Evaluates: Evaluate allowed authentication factor types from /admin/v1/settings including push_enabled,
           sms_enabled, voice_enabled, mobile_otp_enabled, and u2f_enabled fields to determine which
           authentication methods are permitted and whether at least one strong method is enabled.
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
                "transformationId": "authTypesAllowed",
                "vendor": "Duo",
                "category": "iam"
            }
        }
    }


def get_settings(data):
    if isinstance(data, dict):
        candidate = data.get("response", None)
        if isinstance(candidate, dict):
            return candidate
        return data
    return {}


def evaluate(data):
    try:
        settings = get_settings(data)

        push_enabled = bool(settings.get("push_enabled", False))
        sms_enabled = bool(settings.get("sms_enabled", False))
        voice_enabled = bool(settings.get("voice_enabled", False))
        mobile_otp_enabled = bool(settings.get("mobile_otp_enabled", False))
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
        if u2f_enabled:
            allowed_types.append("u2f")

        strong_auth_enabled = push_enabled or mobile_otp_enabled or u2f_enabled
        total_allowed = len(allowed_types)

        return {
            "authTypesAllowed": strong_auth_enabled,
            "pushEnabled": push_enabled,
            "smsEnabled": sms_enabled,
            "voiceEnabled": voice_enabled,
            "mobileOtpEnabled": mobile_otp_enabled,
            "u2fEnabled": u2f_enabled,
            "allowedAuthTypes": allowed_types,
            "totalAllowedTypes": total_allowed
        }
    except Exception as e:
        return {"authTypesAllowed": False, "error": str(e)}


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
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        allowed_types = extra_fields.get("allowedAuthTypes", [])
        total_allowed = extra_fields.get("totalAllowedTypes", 0)

        if result_value:
            pass_reasons.append("At least one strong authentication method is enabled: " + ", ".join(allowed_types))
            pass_reasons.append("totalAllowedTypes: " + str(total_allowed))
        else:
            fail_reasons.append("No strong authentication methods are enabled — push, mobile OTP, and U2F are all disabled")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Enable at least one strong authentication factor in Duo settings — Duo Push (push_enabled), Mobile OTP (mobile_otp_enabled), or U2F/WebAuthn (u2f_enabled) are recommended over SMS or voice")

        if extra_fields.get("smsEnabled", False):
            additional_findings.append("SMS authentication is enabled — SMS-based OTP is susceptible to SIM-swapping and interception; consider restricting it in favour of stronger methods")
        if extra_fields.get("voiceEnabled", False):
            additional_findings.append("Voice call authentication is enabled — voice callbacks are a weaker factor; consider disabling in favour of app-based methods")

        result_dict = {criteriaKey: result_value}
        for k in extra_fields:
            result_dict[k] = extra_fields[k]

        return create_response(
            result=result_dict,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                criteriaKey: result_value,
                "totalAllowedTypes": total_allowed,
                "allowedAuthTypes": allowed_types
            }
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
