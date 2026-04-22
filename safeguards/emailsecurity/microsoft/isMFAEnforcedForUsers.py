"""
Transformation: isMFAEnforcedForUsers
Vendor: Microsoft  |  Category: emailsecurity
Evaluates: Inspects the tenant's authenticationMethodsPolicy to confirm at least one strong MFA method is enabled.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for loop_idx in range(3):
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isMFAEnforcedForUsers", "vendor": "Microsoft", "category": "emailsecurity"}
        }
    }


STRONG_MFA_METHODS = [
    "microsoftauthenticator",
    "fido2",
    "x509certificate",
    "windowshelloforbusiness",
    "temporaryaccesspass"
]


def evaluate(data):
    try:
        auth_configs = data.get("authenticationMethodConfigurations", [])
        if not auth_configs:
            nested = data.get("getAuthMethodsPolicy", {})
            if isinstance(nested, dict):
                auth_configs = nested.get("authenticationMethodConfigurations", [])
        if not isinstance(auth_configs, list):
            auth_configs = []
        policy_version = data.get("policyVersion", "")
        total_methods = len(auth_configs)
        enabled_strong_methods = []
        all_enabled_methods = []
        for config in auth_configs:
            method_id = config.get("id", "").lower()
            state = config.get("state", "").lower()
            if state == "enabled":
                all_enabled_methods.append(config.get("id", ""))
                for strong in STRONG_MFA_METHODS:
                    if strong in method_id:
                        enabled_strong_methods.append(config.get("id", ""))
                        break
        is_enforced = len(enabled_strong_methods) > 0
        return {
            "isMFAEnforcedForUsers": is_enforced,
            "enabledStrongMfaMethods": ", ".join(enabled_strong_methods) if enabled_strong_methods else "None",
            "allEnabledMethods": ", ".join(all_enabled_methods) if all_enabled_methods else "None",
            "totalMethodsConfigured": total_methods,
            "policyVersion": policy_version
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
            pass_reasons.append("Strong MFA methods are enabled in the authentication methods policy")
            pass_reasons.append("Enabled strong methods: " + eval_result.get("enabledStrongMfaMethods", ""))
        else:
            fail_reasons.append("No strong MFA methods (Microsoft Authenticator, FIDO2, certificate) are enabled")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Enable Microsoft Authenticator or FIDO2 in the Authentication Methods policy under Microsoft Entra ID > Security > Authentication methods")
        merged_result = {criteriaKey: result_value}
        for k in extra_fields:
            merged_result[k] = extra_fields[k]
        return create_response(
            result=merged_result, validation=validation,
            pass_reasons=pass_reasons, fail_reasons=fail_reasons, recommendations=recommendations,
            input_summary={"totalMethodsConfigured": eval_result.get("totalMethodsConfigured", 0), "enabledStrongMfaMethods": eval_result.get("enabledStrongMfaMethods", "None")})
    except Exception as e:
        return create_response(
            result={criteriaKey: False}, validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)], fail_reasons=["Transformation error: " + str(e)])
