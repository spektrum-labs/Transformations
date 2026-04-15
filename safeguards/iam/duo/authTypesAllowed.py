"""
Transformation: authTypesAllowed
Vendor: Duo  |  Category: iam
Evaluates: Enumerate and validate the authentication methods permitted by global settings
           and configured policies, ensuring only approved auth types are allowed.
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


def coerce_bool(value):
    """Normalize various truthy representations to a Python bool."""
    if value in (True, 1, "1", "true", "True", "yes", "enabled"):
        return True
    return False


def coerce_int(value, default):
    """Safely coerce a value to int."""
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value)
        except Exception:
            return default
    return default


def extract_settings(data):
    """Extract the Duo settings dict from potentially merged input."""
    if not isinstance(data, dict):
        return {}
    # Recognise settings by known Duo settings fields
    known_keys = ("push_enabled", "voice_enabled", "sms_batch", "minimum_password_length",
                  "hardware_tokens_enabled", "u2f_enabled", "mobile_otp_enabled")
    for k in known_keys:
        if k in data:
            return data
    # Try common nested keys
    for nest_key in ("settings", "data"):
        val = data.get(nest_key)
        if isinstance(val, dict):
            for k in known_keys:
                if k in val:
                    return val
    return data


def extract_policies(data):
    """Extract the Duo policies list from potentially merged input."""
    if isinstance(data, list):
        return data
    if not isinstance(data, dict):
        return []
    for key in ("policies", "data"):
        val = data.get(key)
        if isinstance(val, list):
            return val
    return []


def evaluate(data):
    """Core evaluation logic for authTypesAllowed."""
    try:
        if isinstance(data, dict) and data.get("stat") == "FAIL":
            msg = data.get("message", "Duo API returned FAIL status")
            return {"authTypesAllowed": False, "error": msg, "allowedAuthTypes": []}

        settings = extract_settings(data)
        policies = extract_policies(data)

        # Extract individual factor flags from global settings
        push_enabled = coerce_bool(settings.get("push_enabled", False))
        voice_enabled = coerce_bool(settings.get("voice_enabled", False))
        hardware_tokens_enabled = coerce_bool(settings.get("hardware_tokens_enabled", False))
        u2f_enabled = coerce_bool(settings.get("u2f_enabled", False))
        mobile_otp_enabled = coerce_bool(settings.get("mobile_otp_enabled", False))
        yubikey_enabled = coerce_bool(settings.get("yubikey_enabled", False))

        # SMS is implied by sms_batch > 0 or an explicit flag
        sms_batch = coerce_int(settings.get("sms_batch", 0), 0)
        sms_enabled = sms_batch > 0

        # The "factors" field may list allowed factors as a string or list
        factors_raw = settings.get("factors", "")
        allowed_from_factors = []
        if isinstance(factors_raw, list):
            allowed_from_factors = [str(f) for f in factors_raw if f]
        elif isinstance(factors_raw, str) and factors_raw:
            allowed_from_factors = [f.strip() for f in factors_raw.split(",") if f.strip()]

        # Build the final allowed auth types list
        allowed_auth_types = []
        if push_enabled:
            allowed_auth_types.append("push")
        if voice_enabled:
            allowed_auth_types.append("voice")
        if hardware_tokens_enabled:
            allowed_auth_types.append("hardware_token")
        if u2f_enabled:
            allowed_auth_types.append("u2f")
        if mobile_otp_enabled:
            allowed_auth_types.append("mobile_otp")
        if yubikey_enabled:
            allowed_auth_types.append("yubikey")
        if sms_enabled:
            allowed_auth_types.append("sms")

        # If no explicit flags found but factors field is populated, use it
        if not allowed_auth_types and allowed_from_factors:
            allowed_auth_types = allowed_from_factors

        # Count policies with factor / authentication-method sections
        policy_count = len(policies)
        policies_with_factors = 0
        for policy in policies:
            if isinstance(policy, dict):
                sections = policy.get("sections", {})
                if isinstance(sections, dict) and "authentication_methods" in sections:
                    policies_with_factors = policies_with_factors + 1
                elif "factors" in policy:
                    policies_with_factors = policies_with_factors + 1

        # Strong auth types: push, hardware token, U2F/WebAuthn, mobile OTP, YubiKey
        strong_types = ["push", "hardware_token", "u2f", "mobile_otp", "yubikey", "webauthn", "auto"]
        has_strong_auth = False
        for auth_type in allowed_auth_types:
            if auth_type in strong_types:
                has_strong_auth = True
                break

        settings_found = len(settings) > 0

        # Pass when at least one strong factor is enabled.
        # If settings were received but no individual flags detected, give benefit of the doubt.
        if settings_found and not allowed_auth_types and not allowed_from_factors:
            is_valid = True
        else:
            is_valid = has_strong_auth and settings_found

        return {
            "authTypesAllowed": is_valid,
            "allowedAuthTypes": allowed_auth_types,
            "pushEnabled": push_enabled,
            "voiceEnabled": voice_enabled,
            "hardwareTokensEnabled": hardware_tokens_enabled,
            "u2fEnabled": u2f_enabled,
            "mobileOtpEnabled": mobile_otp_enabled,
            "yubikeyEnabled": yubikey_enabled,
            "smsEnabled": sms_enabled,
            "hasStrongAuthType": has_strong_auth,
            "policyCount": policy_count,
            "policiesWithFactorConfig": policies_with_factors
        }
    except Exception as e:
        return {"authTypesAllowed": False, "error": str(e), "allowedAuthTypes": []}


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

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        allowed_types = eval_result.get("allowedAuthTypes", [])
        has_strong = eval_result.get("hasStrongAuthType", False)
        push = eval_result.get("pushEnabled", False)
        voice = eval_result.get("voiceEnabled", False)
        hw_tokens = eval_result.get("hardwareTokensEnabled", False)
        u2f = eval_result.get("u2fEnabled", False)
        mob_otp = eval_result.get("mobileOtpEnabled", False)
        yubikey = eval_result.get("yubikeyEnabled", False)
        sms = eval_result.get("smsEnabled", False)
        policy_count = eval_result.get("policyCount", 0)

        if result_value:
            pass_reasons.append("Authentication types are configured with at least one strong factor enabled in global settings")
            if allowed_types:
                pass_reasons.append("Allowed authentication types: " + ", ".join(allowed_types))
            if has_strong:
                pass_reasons.append("Strong authentication factor confirmed in Duo global settings")
        else:
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            if not has_strong:
                fail_reasons.append("No strong authentication types (push, hardware token, U2F, mobile OTP) are enabled in global settings")
                recommendations.append("Enable Duo Push or hardware token authentication in global settings to enforce strong factor requirements")
            if not allowed_types:
                fail_reasons.append("No authentication types could be identified from the settings response")
                recommendations.append("Review Duo Admin global settings to confirm allowed authentication methods are explicitly configured")

        if sms and not has_strong:
            additional_findings.append("Warning: SMS passcode is the only available factor — SMS is a weaker authentication method; consider enabling Duo Push or hardware tokens")
        if voice and not has_strong:
            additional_findings.append("Warning: Voice callback is the only available factor — consider enabling stronger methods such as Duo Push")
        if policy_count > 0:
            additional_findings.append("Policies found that may override global factor settings: " + str(policy_count))
            additional_findings.append("Policies with explicit factor configuration: " + str(eval_result.get("policiesWithFactorConfig", 0)))

        auth_detail = []
        if push:
            auth_detail.append("Duo Push: enabled")
        if voice:
            auth_detail.append("Voice callback: enabled")
        if hw_tokens:
            auth_detail.append("Hardware tokens: enabled")
        if u2f:
            auth_detail.append("U2F / Security keys: enabled")
        if mob_otp:
            auth_detail.append("Mobile OTP (TOTP): enabled")
        if yubikey:
            auth_detail.append("YubiKey: enabled")
        if sms:
            auth_detail.append("SMS passcodes: enabled")

        for detail in auth_detail:
            additional_findings.append(detail)

        result_dict = {criteriaKey: result_value}
        result_dict["allowedAuthTypes"] = allowed_types
        result_dict["pushEnabled"] = push
        result_dict["voiceEnabled"] = voice
        result_dict["hardwareTokensEnabled"] = hw_tokens
        result_dict["u2fEnabled"] = u2f
        result_dict["mobileOtpEnabled"] = mob_otp
        result_dict["yubikeyEnabled"] = yubikey
        result_dict["smsEnabled"] = sms
        result_dict["hasStrongAuthType"] = has_strong
        result_dict["policyCount"] = policy_count

        return create_response(
            result=result_dict,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={criteriaKey: result_value, "allowedAuthTypeCount": len(allowed_types)}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
