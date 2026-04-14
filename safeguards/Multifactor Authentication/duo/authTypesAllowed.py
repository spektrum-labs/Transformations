"""
Transformation: authTypesAllowed
Vendor: Duo  |  Category: Multifactor Authentication
Evaluates: Which authentication factor types are permitted in Duo and whether only approved strong factors are enabled.
API Method: getAccountSettings (merge:true) + getPolicies (merge:true)
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "authTypesAllowed", "vendor": "Duo", "category": "Multifactor Authentication"}
        }
    }


def evaluate(data):
    try:
        settings = {}
        policies = []

        if isinstance(data, dict):
            if "getAccountSettings" in data:
                settings = data["getAccountSettings"] if isinstance(data["getAccountSettings"], dict) else {}
            if "getPolicies" in data:
                policies = data["getPolicies"] if isinstance(data["getPolicies"], list) else []
            if not settings and not policies:
                # Flat merged: settings and policies coexist in data
                settings = data

        def to_bool(val):
            if isinstance(val, bool):
                return val
            if val is None:
                return False
            return str(val).lower() in ("true", "1", "yes", "enabled")

        # --- Factor flags from account settings ---
        # Strong factors
        push_enabled = to_bool(settings.get("push_enabled", True))
        webauthn_enabled = to_bool(settings.get("webauthn_enabled", False))
        u2f_enabled = to_bool(settings.get("u2f_enabled", False))
        mobile_otp_enabled = to_bool(settings.get("mobile_otp_enabled", False))
        hardware_token_enabled = to_bool(settings.get("hardware_token_enabled", False))
        # Weak factors
        sms_enabled = to_bool(settings.get("sms_enabled", True))
        voice_enabled = to_bool(settings.get("voice_enabled", True))

        allowed_factors = []
        strong_factors = []
        weak_factors = []

        if push_enabled:
            allowed_factors = allowed_factors + ["Duo Push"]
            strong_factors = strong_factors + ["Duo Push"]
        if webauthn_enabled:
            allowed_factors = allowed_factors + ["WebAuthn / FIDO2"]
            strong_factors = strong_factors + ["WebAuthn / FIDO2"]
        if u2f_enabled:
            allowed_factors = allowed_factors + ["U2F Hardware Token"]
            strong_factors = strong_factors + ["U2F Hardware Token"]
        if mobile_otp_enabled:
            allowed_factors = allowed_factors + ["Mobile OTP (TOTP)"]
            strong_factors = strong_factors + ["Mobile OTP (TOTP)"]
        if hardware_token_enabled:
            allowed_factors = allowed_factors + ["Hardware Token (HOTP)"]
            strong_factors = strong_factors + ["Hardware Token (HOTP)"]
        if sms_enabled:
            allowed_factors = allowed_factors + ["SMS Passcode"]
            weak_factors = weak_factors + ["SMS Passcode"]
        if voice_enabled:
            allowed_factors = allowed_factors + ["Voice Call"]
            weak_factors = weak_factors + ["Voice Call"]

        # Check policies for factor overrides
        policy_restricted_factors = []
        policy_required_factors = []

        for policy in policies:
            if not isinstance(policy, dict):
                continue
            sections = policy.get("sections", {})
            if not isinstance(sections, dict):
                continue
            auth_section = sections.get("authentication", {})
            if not isinstance(auth_section, dict):
                continue
            required = auth_section.get("required_factor", "")
            if required and required not in policy_required_factors:
                policy_required_factors = policy_required_factors + [required]
            factors_map = auth_section.get("factors", {})
            if isinstance(factors_map, dict):
                for factor_key in factors_map:
                    factor_val = factors_map[factor_key]
                    if str(factor_val).lower() in ("deny", "false", "disabled", "0"):
                        if factor_key not in policy_restricted_factors:
                            policy_restricted_factors = policy_restricted_factors + [factor_key]

        has_strong_factors = len(strong_factors) > 0
        has_weak_only = has_strong_factors is False and len(weak_factors) > 0
        weak_factors_restricted_by_policy = len(policy_restricted_factors) > 0

        # Pass if strong factors are available and no weak-only scenario
        auth_types_acceptable = has_strong_factors

        return {
            "authTypesAllowed": auth_types_acceptable,
            "allowedFactors": allowed_factors,
            "strongFactors": strong_factors,
            "weakFactors": weak_factors,
            "totalFactorsEnabled": len(allowed_factors),
            "strongFactorCount": len(strong_factors),
            "weakFactorCount": len(weak_factors),
            "policyRequiredFactors": policy_required_factors,
            "policyRestrictedFactors": policy_restricted_factors,
            "weakFactorsRestrictedByPolicy": weak_factors_restricted_by_policy
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
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        allowed = eval_result.get("allowedFactors", [])
        strong = eval_result.get("strongFactors", [])
        weak = eval_result.get("weakFactors", [])
        policy_required = eval_result.get("policyRequiredFactors", [])
        policy_restricted = eval_result.get("policyRestrictedFactors", [])
        weak_restricted = eval_result.get("weakFactorsRestrictedByPolicy", False)

        if result_value:
            pass_reasons.append("At least one strong authentication factor is enabled in Duo")
            pass_reasons.append("Strong factors enabled: " + ", ".join(strong))
            if weak_restricted:
                pass_reasons.append("Weak factors are restricted by policy: " + ", ".join(policy_restricted))
            if policy_required:
                pass_reasons.append("Policies require specific strong factors: " + ", ".join(policy_required))
        else:
            fail_reasons.append("No strong authentication factors are enabled in Duo account settings")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Enable Duo Push and/or WebAuthn in account settings as primary strong authentication factors")
            recommendations.append("Disable or restrict SMS and voice call factors via policy to prevent downgrade attacks")

        if weak and not weak_restricted:
            additional_findings.append("Weak factors are currently enabled and not restricted by policy: " + ", ".join(weak) + ". Consider restricting these via a Duo policy.")
        if len(allowed) == 0:
            additional_findings.append("No authentication factors detected. Verify account settings permissions include 'Grant read information'.")

        return create_response(
            result={
                criteriaKey: result_value,
                "allowedFactors": allowed,
                "strongFactors": strong,
                "weakFactors": weak,
                "totalFactorsEnabled": eval_result.get("totalFactorsEnabled", 0),
                "strongFactorCount": eval_result.get("strongFactorCount", 0),
                "weakFactorCount": eval_result.get("weakFactorCount", 0),
                "policyRequiredFactors": policy_required,
                "policyRestrictedFactors": policy_restricted
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"allowedFactors": allowed, "strongFactorCount": eval_result.get("strongFactorCount", 0), "weakFactorCount": eval_result.get("weakFactorCount", 0)}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
