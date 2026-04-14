"""
Transformation: isStrongAuthRequired
Vendor: Duo  |  Category: Multifactor Authentication
Evaluates: Whether strong authentication factors are required across account settings and policies.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isStrongAuthRequired", "vendor": "Duo", "category": "Multifactor Authentication"}
        }
    }


def evaluate(data):
    try:
        # Merged input: may be keyed by method name or flat-merged
        settings = {}
        policies = []

        if isinstance(data, dict):
            if "getAccountSettings" in data:
                settings = data["getAccountSettings"] if isinstance(data["getAccountSettings"], dict) else {}
            if "getPolicies" in data:
                policies = data["getPolicies"] if isinstance(data["getPolicies"], list) else []
            # Flat merge fallback: settings fields coexist with policies list
            if not settings and not policies:
                settings = data

        # Strong auth factor indicators from account settings
        push_enabled = settings.get("push_enabled", True)
        webauthn_enabled = settings.get("webauthn_enabled", False)
        u2f_enabled = settings.get("u2f_enabled", False)
        mobile_otp_enabled = settings.get("mobile_otp_enabled", False)
        sms_enabled = settings.get("sms_enabled", True)
        voice_enabled = settings.get("voice_enabled", True)

        # Convert to bool safely
        def to_bool(val):
            if isinstance(val, bool):
                return val
            return str(val).lower() in ("true", "1", "yes")

        push_on = to_bool(push_enabled)
        webauthn_on = to_bool(webauthn_enabled)
        u2f_on = to_bool(u2f_enabled)
        mobile_otp_on = to_bool(mobile_otp_enabled)
        sms_on = to_bool(sms_enabled)
        voice_on = to_bool(voice_enabled)

        # Strong factors: Duo Push, WebAuthn, U2F, TOTP/mobile OTP
        # Weak factors: SMS, voice call
        has_strong_factor = push_on or webauthn_on or u2f_on or mobile_otp_on
        only_weak_factors = (not has_strong_factor) and (sms_on or voice_on)

        # Check policies for strong auth enforcement
        policy_enforces_strong = False
        enforcing_policies = []
        for policy in policies:
            if not isinstance(policy, dict):
                continue
            sections = policy.get("sections", {})
            if not isinstance(sections, dict):
                continue
            auth_section = sections.get("authentication", {})
            if not isinstance(auth_section, dict):
                continue
            # If policy restricts to strong factors only
            required_factor = auth_section.get("required_factor", "")
            factors_blocked = auth_section.get("factors", {})
            if required_factor in ("duo_push", "hardware_token", "webauthn", "duo_mobile_passcode"):
                policy_enforces_strong = True
                enforcing_policies = enforcing_policies + [policy.get("policy_name", "unnamed")]
            # SMS/Voice blocked explicitly = strong auth enforced
            if isinstance(factors_blocked, dict):
                sms_blocked = str(factors_blocked.get("sms", "")).lower() in ("deny", "false", "disabled")
                voice_blocked = str(factors_blocked.get("phone", "")).lower() in ("deny", "false", "disabled")
                if sms_blocked and voice_blocked and has_strong_factor:
                    policy_enforces_strong = True
                    policy_name = policy.get("policy_name", "unnamed")
                    if policy_name not in enforcing_policies:
                        enforcing_policies = enforcing_policies + [policy_name]

        is_strong_auth_required = has_strong_factor and (not only_weak_factors)

        enabled_strong = []
        if push_on:
            enabled_strong = enabled_strong + ["Duo Push"]
        if webauthn_on:
            enabled_strong = enabled_strong + ["WebAuthn"]
        if u2f_on:
            enabled_strong = enabled_strong + ["U2F Hardware Token"]
        if mobile_otp_on:
            enabled_strong = enabled_strong + ["Mobile OTP"]

        enabled_weak = []
        if sms_on:
            enabled_weak = enabled_weak + ["SMS"]
        if voice_on:
            enabled_weak = enabled_weak + ["Voice Call"]

        return {
            "isStrongAuthRequired": is_strong_auth_required,
            "strongFactorsEnabled": enabled_strong,
            "weakFactorsEnabled": enabled_weak,
            "policyEnforcesStrongAuth": policy_enforces_strong,
            "enforcingPolicies": enforcing_policies,
            "totalPoliciesChecked": len(policies)
        }
    except Exception as e:
        return {"isStrongAuthRequired": False, "error": str(e)}


def transform(input):
    criteriaKey = "isStrongAuthRequired"
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

        strong_factors = eval_result.get("strongFactorsEnabled", [])
        weak_factors = eval_result.get("weakFactorsEnabled", [])
        enforcing_policies = eval_result.get("enforcingPolicies", [])

        if result_value:
            pass_reasons.append("Strong authentication factors are enabled in Duo account settings")
            pass_reasons.append("Strong factors available: " + ", ".join(strong_factors))
            if enforcing_policies:
                pass_reasons.append("Policies enforcing strong auth: " + ", ".join(enforcing_policies))
        else:
            fail_reasons.append("No strong authentication factors are enabled or configured")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Enable Duo Push, WebAuthn, or hardware token factors in account settings")
            recommendations.append("Create a policy that restricts authentication to strong factors only")

        if weak_factors:
            additional_findings.append("Weak factors still enabled: " + ", ".join(weak_factors) + ". Consider restricting these via policy.")

        return create_response(
            result={
                criteriaKey: result_value,
                "strongFactorsEnabled": strong_factors,
                "weakFactorsEnabled": weak_factors,
                "policyEnforcesStrongAuth": eval_result.get("policyEnforcesStrongAuth", False),
                "enforcingPolicies": enforcing_policies,
                "totalPoliciesChecked": eval_result.get("totalPoliciesChecked", 0)
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={"strongFactorsEnabled": strong_factors, "weakFactorsEnabled": weak_factors}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
