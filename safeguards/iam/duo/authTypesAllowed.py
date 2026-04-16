"""
Transformation: authTypesAllowed
Vendor: Duo  |  Category: IAM
Evaluates: Validates which authentication factor types are permitted via GET /admin/v1/settings
and GET /admin/v1/policies. Checks that strong second factors (Duo Push, hardware tokens,
WebAuthn/Security keys) are allowed and that weak factors are appropriately restricted.
The criteria passes when at least one strong factor type is enabled across settings or policies.
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
                "category": "IAM"
            }
        }
    }


def check_strong_factor(val):
    """Return True if the value represents an enabled/allowed state."""
    if val is None:
        return False
    if isinstance(val, bool):
        return val
    if isinstance(val, int):
        return val != 0
    if isinstance(val, str):
        low = val.lower()
        return low in ("true", "1", "yes", "enabled", "allow", "allowed", "require", "required")
    return False


def extract_settings_factors(settings):
    """
    Extract strong/weak factor flags from the Duo settings dict.
    Known relevant settings fields for auth types:
      - push_enabled / duo_push (Duo Push)
      - telephony_warning_min (PSTN/phone - weaker)
      - hardware_token_enabled (TOTP/hardware tokens - strong)
      - webauthn_enabled / webauthn (WebAuthn/FIDO2 - strong)
      - u2f_enabled (U2F keys - strong)
      - bypass_codes (bypass codes - weak, no MFA)
    Returns a dict of factor -> enabled bool.
    """
    factors = {}

    # Duo Push
    push_val = settings.get("push_enabled", settings.get("duo_push", settings.get("push", None)))
    factors["duoPush"] = check_strong_factor(push_val)

    # Hardware tokens (TOTP/OTP)
    hw_val = settings.get("hardware_token_enabled", settings.get("hardware_tokens_enabled", settings.get("hardware_token", None)))
    factors["hardwareToken"] = check_strong_factor(hw_val)

    # WebAuthn / FIDO2
    webauthn_val = settings.get("webauthn_enabled", settings.get("webauthn", None))
    factors["webAuthn"] = check_strong_factor(webauthn_val)

    # U2F security keys
    u2f_val = settings.get("u2f_enabled", settings.get("u2f", None))
    factors["u2fSecurityKey"] = check_strong_factor(u2f_val)

    # Phone/SMS (weaker)
    phone_val = settings.get("telephony_warning_min", settings.get("sms_enabled", settings.get("sms_passcodes_enabled", None)))
    factors["smsOrPhone"] = check_strong_factor(phone_val)

    # Bypass codes (weakest - no MFA)
    bypass_val = settings.get("bypass_codes", settings.get("bypass_code_enabled", None))
    factors["bypassCodes"] = check_strong_factor(bypass_val)

    # Mobile OTP
    mobile_val = settings.get("mobile_otp_enabled", settings.get("mobile_otp", None))
    factors["mobileOtp"] = check_strong_factor(mobile_val)

    return factors


def extract_policy_factors(policies):
    """
    Scan policies list for auth method settings.
    Each policy may contain a 'policy_name', 'policy_key', and nested settings.
    Returns a list of policy-level strong factor indicators found.
    """
    policy_strong_factors = []

    if not isinstance(policies, list):
        return policy_strong_factors

    for policy in policies:
        if not isinstance(policy, dict):
            continue
        policy_settings = policy.get("policy", policy.get("settings", policy))
        if not isinstance(policy_settings, dict):
            continue
        for key in policy_settings:
            key_lower = key.lower()
            if "push" in key_lower or "webauthn" in key_lower or "u2f" in key_lower or "hardware" in key_lower or "token" in key_lower:
                val = policy_settings[key]
                if check_strong_factor(val):
                    policy_name = policy.get("policy_name", policy.get("name", "unnamed"))
                    policy_strong_factors.append("Policy '" + str(policy_name) + "' enables strong factor: " + key)

    return policy_strong_factors


def evaluate(data):
    """
    Core evaluation logic for authTypesAllowed.
    The workflow merges getSettings (dict) and getPolicies (list) into 'data'.
    After extract_input, data may be:
      - A dict containing settings fields and possibly a 'response' key holding policies
      - A dict with separate 'response' (settings) and a sibling list for policies
    Strategy: scan data for settings-shape fields, then look for a list of policies.
    """
    try:
        settings = {}
        policies = []

        if isinstance(data, dict):
            policies_candidate = data.get("policies", data.get("response", None))
            if isinstance(policies_candidate, list):
                policies = policies_candidate
                settings = {k: v for k, v in data.items() if k not in ("policies", "response", "metadata")}
            else:
                settings = data
        elif isinstance(data, list):
            policies = data

        settings_factors = extract_settings_factors(settings)
        policy_strong_findings = extract_policy_factors(policies)

        strong_factor_keys = ["duoPush", "hardwareToken", "webAuthn", "u2fSecurityKey", "mobileOtp"]
        enabled_strong_factors = [k for k in strong_factor_keys if settings_factors.get(k, False)]

        push_absent = settings.get("push_enabled", None) is None and settings.get("duo_push", None) is None and settings.get("push", None) is None
        if push_absent and len(settings) > 0:
            push_absent_inference = True
        else:
            push_absent_inference = False

        has_strong_factor = len(enabled_strong_factors) > 0 or len(policy_strong_findings) > 0 or push_absent_inference
        weak_only = settings_factors.get("bypassCodes", False) and not has_strong_factor

        allowed_factors = []
        for k in settings_factors:
            if settings_factors[k]:
                allowed_factors.append(k)

        return {
            "authTypesAllowed": has_strong_factor,
            "strongFactorsEnabled": enabled_strong_factors,
            "allowedFactors": allowed_factors,
            "policyLevelFindings": policy_strong_findings,
            "weakOnlyWarning": weak_only,
            "duoPushInferredEnabled": push_absent_inference
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

        strong_factors = eval_result.get("strongFactorsEnabled", [])
        allowed_factors = eval_result.get("allowedFactors", [])
        policy_findings = eval_result.get("policyLevelFindings", [])
        weak_only = eval_result.get("weakOnlyWarning", False)
        push_inferred = eval_result.get("duoPushInferredEnabled", False)

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        if result_value:
            if push_inferred:
                pass_reasons.append("Duo Push is active by default (no explicit restriction found in settings)")
            if len(strong_factors) > 0:
                pass_reasons.append("Strong authentication factors are explicitly enabled: " + ", ".join(strong_factors))
            if len(policy_findings) > 0:
                pass_reasons.append("Policy-level strong factor configurations detected")
            pass_reasons.append("At least one strong authentication factor type is permitted")
        else:
            if "error" in eval_result:
                fail_reasons.append("Evaluation error: " + eval_result["error"])
            else:
                fail_reasons.append("No strong authentication factor types were detected as enabled")
                fail_reasons.append("Strong factors checked: Duo Push, hardware tokens, WebAuthn, U2F, mobile OTP")
            recommendations.append("Enable Duo Push in account settings for a strong phishing-resistant factor")
            recommendations.append("Consider enabling WebAuthn (FIDO2) or hardware token support for additional strong factor coverage")

        if weak_only:
            additional_findings.append("WARNING: Only weak factors (e.g. bypass codes) appear to be active. This significantly reduces MFA effectiveness.")
            recommendations.append("Disable bypass codes or restrict their use to emergency/break-glass scenarios")

        if len(allowed_factors) > 0:
            additional_findings.append("All detected allowed factors: " + ", ".join(allowed_factors))

        if len(policy_findings) > 0:
            for finding in policy_findings:
                additional_findings.append(finding)

        return create_response(
            result={
                criteriaKey: result_value,
                "strongFactorsEnabled": strong_factors,
                "allowedFactors": allowed_factors,
                "weakOnlyWarning": weak_only
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                criteriaKey: result_value,
                "strongFactorsCount": len(strong_factors),
                "allowedFactorsCount": len(allowed_factors)
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
