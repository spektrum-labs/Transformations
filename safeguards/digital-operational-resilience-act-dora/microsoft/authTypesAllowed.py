"""
Transformation: authTypesAllowed
Vendor: Microsoft  |  Category: digital-operational-resilience-act-dora
Evaluates: Whether only strong authentication methods are enabled in the tenant authentication methods policy.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "authTypesAllowed", "vendor": "Microsoft", "category": "digital-operational-resilience-act-dora"}
        }
    }


def evaluate(data):
    try:
        configurations = data.get("authenticationMethodConfigurations", [])
        weak_methods = ["Sms", "Email", "Voice", "TemporaryAccessPass"]
        enabled_methods = []
        disabled_methods = []
        weak_enabled = []
        strong_enabled = []
        for config in configurations:
            method_id = config.get("id", "")
            state = config.get("state", "disabled")
            if state.lower() == "enabled":
                enabled_methods.append(method_id)
                is_weak = False
                for w in weak_methods:
                    if w.lower() == method_id.lower():
                        is_weak = True
                        break
                if is_weak:
                    weak_enabled.append(method_id)
                else:
                    strong_enabled.append(method_id)
            else:
                disabled_methods.append(method_id)
        only_strong = len(weak_enabled) == 0 and len(strong_enabled) > 0
        return {
            "authTypesAllowed": only_strong,
            "enabledMethods": enabled_methods,
            "weakMethodsEnabled": weak_enabled,
            "strongMethodsEnabled": strong_enabled,
            "disabledMethods": disabled_methods
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
            return create_response(result={criteriaKey: False}, validation=validation, fail_reasons=["Input validation failed"])
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if result_value:
            pass_reasons.append("Only strong authentication methods are enabled")
            pass_reasons.append("Strong methods enabled: " + str(extra_fields.get("strongMethodsEnabled", [])))
        else:
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            elif extra_fields.get("weakMethodsEnabled"):
                fail_reasons.append("Weak authentication methods are enabled: " + str(extra_fields.get("weakMethodsEnabled", [])))
                recommendations.append("Disable weak authentication methods (SMS, Email OTP, Voice) and enforce strong methods such as FIDO2 or Microsoft Authenticator per DORA strong authentication requirements")
            else:
                fail_reasons.append("No strong authentication methods are enabled")
                recommendations.append("Enable strong authentication methods such as FIDO2 or Microsoft Authenticator")
        result_dict = {criteriaKey: result_value}
        for k in extra_fields:
            result_dict[k] = extra_fields[k]
        summary_dict = {criteriaKey: result_value}
        for k in extra_fields:
            summary_dict[k] = extra_fields[k]
        return create_response(
            result=result_dict, validation=validation,
            pass_reasons=pass_reasons, fail_reasons=fail_reasons, recommendations=recommendations,
            input_summary=summary_dict)
    except Exception as e:
        return create_response(
            result={criteriaKey: False}, validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)], fail_reasons=["Transformation error: " + str(e)])
