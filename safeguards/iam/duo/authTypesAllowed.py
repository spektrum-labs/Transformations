"""
Transformation: authTypesAllowed
Vendor: Duo  |  Category: iam
Evaluates: Validates the permitted authentication methods by inspecting the settings
           response from GET /admin/v1/settings. Confirms that only strong, approved
           authentication types (Duo Push, TOTP, hardware token) are permitted and that
           weak methods such as SMS-only or voice-only are not the sole allowed factors.
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


STRONG_METHODS = ["push", "token", "totp", "passcode", "webauthn-platform", "webauthn-roaming", "mobile_otp"]
WEAK_ONLY_METHODS = ["sms", "phone", "voice"]


def has_strong_method(methods):
    for method in methods:
        method_lower = method.lower()
        for strong in STRONG_METHODS:
            if strong in method_lower:
                return True
    return False


def is_weak_only(methods):
    if len(methods) == 0:
        return False
    for method in methods:
        method_lower = method.lower()
        is_weak = False
        for weak in WEAK_ONLY_METHODS:
            if weak in method_lower:
                is_weak = True
                break
        if not is_weak:
            return False
    return True


def evaluate(data):
    try:
        settings = data.get("settings", {})
        if not settings:
            settings = data

        effective_auth_policy = settings.get("effective_auth_policy", "")
        allowed_auth_methods = settings.get("allowed_auth_methods", [])

        findings = []
        failures = []
        strong_present = False
        weak_only_flag = False
        methods_configured = []

        if isinstance(allowed_auth_methods, list) and len(allowed_auth_methods) > 0:
            methods_configured = [str(m) for m in allowed_auth_methods]
            strong_present = has_strong_method(methods_configured)
            weak_only_flag = is_weak_only(methods_configured)

            if strong_present:
                findings.append("Strong authentication method(s) are configured: " + ", ".join(methods_configured))
            if weak_only_flag:
                failures.append("Only weak methods (SMS/voice) are configured: " + ", ".join(methods_configured))
        else:
            push_enabled = settings.get("push_enabled", True)
            sms_enabled = settings.get("sms_enabled", False)
            voice_enabled = settings.get("voice_enabled", False)
            mobile_otp_enabled = settings.get("mobile_otp_enabled", True)
            hardware_token_enabled = settings.get("hardware_token_enabled", False)

            if push_enabled:
                methods_configured.append("push")
                strong_present = True
                findings.append("Duo Push is enabled")
            if mobile_otp_enabled:
                methods_configured.append("mobile_otp")
                strong_present = True
                findings.append("Mobile OTP is enabled")
            if hardware_token_enabled:
                methods_configured.append("hardware_token")
                strong_present = True
                findings.append("Hardware token is enabled")
            if sms_enabled:
                methods_configured.append("sms")
                findings.append("SMS passcode is enabled (acceptable if strong methods also present)")
            if voice_enabled:
                methods_configured.append("voice")
                findings.append("Voice callback is enabled (acceptable if strong methods also present)")

            if not push_enabled and not mobile_otp_enabled and not hardware_token_enabled:
                if sms_enabled or voice_enabled:
                    weak_only_flag = True
                    failures.append("No strong authentication methods are enabled; only weak methods (SMS/voice) are active")
                else:
                    findings.append("No explicit auth method flags found; relying on effective_auth_policy")

        if effective_auth_policy:
            findings.append("effective_auth_policy: " + str(effective_auth_policy))
        else:
            findings.append("effective_auth_policy is not set or empty")

        auth_types_allowed = strong_present and not weak_only_flag

        if not strong_present and not weak_only_flag and not methods_configured:
            auth_types_allowed = True
            findings.append("No explicit method restrictions found; all methods are implicitly allowed including strong methods")

        return {
            "authTypesAllowed": auth_types_allowed,
            "configuredMethods": methods_configured,
            "hasStrongMethod": strong_present,
            "isWeakOnly": weak_only_flag,
            "effectiveAuthPolicy": effective_auth_policy,
            "methodFindings": findings,
            "methodFailures": failures
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
        additional_findings = eval_result.get("methodFindings", [])

        if result_value:
            pass_reasons.append("Strong authentication type(s) are allowed and configured")
            configured = eval_result.get("configuredMethods", [])
            if configured:
                pass_reasons.append("Configured methods: " + ", ".join(configured))
            if eval_result.get("effectiveAuthPolicy"):
                pass_reasons.append("Effective auth policy: " + str(eval_result.get("effectiveAuthPolicy")))
        else:
            fail_reasons.append("Authentication type configuration does not meet strong-auth requirements")
            for failure in eval_result.get("methodFailures", []):
                fail_reasons.append(failure)
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Enable strong authentication methods such as Duo Push, TOTP, or hardware tokens in Duo Admin Panel")
            recommendations.append("Ensure SMS-only or voice-only authentication is not the sole permitted factor")

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "settingsPresent": bool(data.get("settings")),
                "methodCount": len(eval_result.get("configuredMethods", [])),
                criteriaKey: result_value
            },
            additional_findings=additional_findings
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
