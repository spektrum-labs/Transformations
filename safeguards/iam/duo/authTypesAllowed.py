"""
Transformation: authTypesAllowed
Vendor: Duo  |  Category: IAM
Evaluates: Determines which authentication factor types are allowed by reading the global
policy's authentication_methods.allowed_2fa_methods object. Returns the enabled/disabled
state for duo_push, hardware_token, phone, sms, voice, and webauthn factors.
Passes when at least one strong authentication method (duo_push, hardware_token, or webauthn)
is enabled.
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


def find_global_policy(policies):
    """Return the global policy object from the policies list, or None."""
    for policy in policies:
        if policy.get("is_global", False):
            return policy
    if len(policies) > 0:
        return policies[0]
    return None


def evaluate(data):
    """
    Read the global policy's authentication_methods.allowed_2fa_methods.
    Passes when at least one strong factor (duo_push, hardware_token, webauthn) is enabled.
    """
    try:
        policies = data.get("policies", [])
        if not policies:
            return {
                "authTypesAllowed": False,
                "error": "No policies found in response",
                "policiesFound": False
            }

        global_policy = find_global_policy(policies)
        if global_policy is None:
            return {
                "authTypesAllowed": False,
                "error": "Could not identify a global policy from the policies list",
                "policiesFound": True
            }

        sections = global_policy.get("sections", {})
        auth_methods = sections.get("authentication_methods", {})
        allowed_methods = auth_methods.get("allowed_2fa_methods", {})

        duo_push = allowed_methods.get("duo_push", False)
        hardware_token = allowed_methods.get("hardware_token", False)
        phone_call = allowed_methods.get("phone", False)
        sms = allowed_methods.get("sms", False)
        voice = allowed_methods.get("voice", False)
        webauthn = allowed_methods.get("webauthn", False)

        strong_auth_enabled = duo_push or hardware_token or webauthn
        weak_methods_enabled = phone_call or sms or voice

        enabled_factors = []
        if duo_push:
            enabled_factors.append("duo_push")
        if hardware_token:
            enabled_factors.append("hardware_token")
        if phone_call:
            enabled_factors.append("phone")
        if sms:
            enabled_factors.append("sms")
        if voice:
            enabled_factors.append("voice")
        if webauthn:
            enabled_factors.append("webauthn")

        return {
            "authTypesAllowed": strong_auth_enabled,
            "duoPushEnabled": duo_push,
            "hardwareTokenEnabled": hardware_token,
            "phoneEnabled": phone_call,
            "smsEnabled": sms,
            "voiceEnabled": voice,
            "webauthnEnabled": webauthn,
            "strongAuthMethodAvailable": strong_auth_enabled,
            "weakMethodsEnabled": weak_methods_enabled,
            "enabledFactors": enabled_factors,
            "totalEnabledFactors": len(enabled_factors),
            "policiesFound": True
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

        extra_fields = {}
        for k in eval_result:
            if k != criteriaKey and k != "error":
                extra_fields[k] = eval_result[k]

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        enabled_factors = eval_result.get("enabledFactors", [])
        enabled_list = ", ".join(enabled_factors) if enabled_factors else "none"

        if result_value:
            pass_reasons.append("At least one strong authentication method is enabled in the global policy")
            if eval_result.get("duoPushEnabled"):
                pass_reasons.append("Duo Push is enabled as a strong authentication factor")
            if eval_result.get("webauthnEnabled"):
                pass_reasons.append("WebAuthn/FIDO2 is enabled as a strong authentication factor")
            if eval_result.get("hardwareTokenEnabled"):
                pass_reasons.append("Hardware tokens are enabled as a strong authentication factor")
            additional_findings.append("All enabled factors: " + enabled_list)
            if eval_result.get("weakMethodsEnabled"):
                additional_findings.append("Weak methods (phone/SMS/voice) are also enabled alongside strong methods")
                recommendations.append("Consider disabling weak authentication methods (phone, SMS, voice) to reduce phishing risk")
        else:
            if eval_result.get("error"):
                fail_reasons.append(eval_result["error"])
            else:
                fail_reasons.append("No strong authentication method (duo_push, hardware_token, webauthn) is enabled in the global policy")
                recommendations.append("Enable Duo Push, WebAuthn, or hardware token authentication in the Duo global policy")
            additional_findings.append("Currently enabled factors: " + enabled_list)

        result_dict = {}
        result_dict[criteriaKey] = result_value
        for k in extra_fields:
            result_dict[k] = extra_fields[k]

        summary_dict = {}
        summary_dict[criteriaKey] = result_value
        for k in extra_fields:
            summary_dict[k] = extra_fields[k]

        return create_response(
            result=result_dict,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary=summary_dict,
            additional_findings=additional_findings
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
