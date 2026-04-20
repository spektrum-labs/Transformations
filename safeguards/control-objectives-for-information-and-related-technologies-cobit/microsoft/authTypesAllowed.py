"""
Transformation: authTypesAllowed
Vendor: Microsoft  |  Category: control-objectives-for-information-and-related-technologies-cobit
Evaluates: Returns the list of enabled authentication method types configured in the tenant's Authentication Methods Policy.
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
        configurations = data.get("authenticationMethodConfigurations", [])
        enabled_types = []
        disabled_types = []
        for config in configurations:
            method_type = config.get("@odata.type", config.get("id", "unknown"))
            state = config.get("state", "")
            if state == "enabled":
                enabled_types.append(method_type)
            else:
                disabled_types.append(method_type)
        has_methods = len(enabled_types) > 0
        return {
            "authTypesAllowed": enabled_types,
            "enabledMethodCount": len(enabled_types),
            "disabledMethodCount": len(disabled_types),
            "disabledTypes": disabled_types,
            "hasEnabledMethods": has_methods
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
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        has_methods = extra_fields.get("hasEnabledMethods", False)
        if has_methods:
            pass_reasons.append("Authentication methods policy returned " + str(extra_fields.get("enabledMethodCount", 0)) + " enabled method(s)")
            pass_reasons.append("Enabled types: " + ", ".join(result_value))
        else:
            fail_reasons.append("No enabled authentication methods found in the policy")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Configure at least one phishing-resistant authentication method (e.g. FIDO2, Microsoft Authenticator) in the Authentication Methods Policy")
        combined = {criteriaKey: result_value}
        for k in extra_fields:
            combined[k] = extra_fields[k]
        return create_response(
            result=combined, validation=validation,
            pass_reasons=pass_reasons, fail_reasons=fail_reasons, recommendations=recommendations,
            input_summary={criteriaKey: result_value, "enabledMethodCount": extra_fields.get("enabledMethodCount", 0)})
    except Exception as e:
        return create_response(
            result={criteriaKey: []}, validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)], fail_reasons=["Transformation error: " + str(e)])
