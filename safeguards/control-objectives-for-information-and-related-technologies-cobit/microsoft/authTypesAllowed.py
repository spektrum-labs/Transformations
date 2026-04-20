"""
Transformation: authTypesAllowed
Vendor: Microsoft  |  Category: control-objectives-for-information-and-related-technologies-cobit
Evaluates: Inspects authenticationMethodConfigurations to enumerate which authentication
method types (e.g. FIDO2, TOTP, SMS) are enabled or disabled in the tenant policy
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "authTypesAllowed", "vendor": "Microsoft", "category": "control-objectives-for-information-and-related-technologies-cobit"}
        }
    }


def evaluate(data):
    try:
        configs = data.get("authenticationMethodConfigurations", [])
        if not configs:
            return {
                "authTypesAllowed": [],
                "reason": "No authentication method configurations found",
                "totalMethodsConfigured": 0,
                "enabledMethodsCount": 0,
                "disabledMethodsCount": 0
            }
        enabled_methods = []
        disabled_methods = []
        for config in configs:
            method_id = config.get("id", "Unknown")
            state = config.get("state", "disabled")
            if state == "enabled":
                enabled_methods.append(method_id)
            else:
                disabled_methods.append(method_id)
        return {
            "authTypesAllowed": enabled_methods,
            "totalMethodsConfigured": len(configs),
            "enabledMethodsCount": len(enabled_methods),
            "disabledMethodsCount": len(disabled_methods),
            "disabledMethods": disabled_methods
        }
    except Exception as e:
        return {"authTypesAllowed": [], "error": str(e)}


def transform(input):
    criteriaKey = "authTypesAllowed"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(result={criteriaKey: []}, validation=validation, fail_reasons=["Input validation failed"])
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, [])
        extra_fields = {}
        for k in eval_result:
            if k != criteriaKey and k != "error" and k != "reason":
                extra_fields[k] = eval_result[k]
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        has_enabled = len(result_value) > 0
        if has_enabled:
            pass_reasons.append("Authentication methods policy is configured with " + str(len(result_value)) + " enabled method(s): " + ", ".join(result_value))
            for k in extra_fields:
                pass_reasons.append(k + ": " + str(extra_fields[k]))
        else:
            fail_reasons.append(criteriaKey + " check failed: No enabled authentication methods found")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            if "reason" in eval_result:
                fail_reasons.append(eval_result["reason"])
            recommendations.append("Enable appropriate authentication methods (e.g. Microsoft Authenticator, FIDO2) in the Authentication Methods Policy in Microsoft Entra ID")
        result_dict = {}
        result_dict[criteriaKey] = result_value
        for k in extra_fields:
            result_dict[k] = extra_fields[k]
        return create_response(
            result=result_dict, validation=validation,
            pass_reasons=pass_reasons, fail_reasons=fail_reasons, recommendations=recommendations,
            input_summary=result_dict)
    except Exception as e:
        return create_response(
            result={criteriaKey: []}, validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)], fail_reasons=["Transformation error: " + str(e)])
