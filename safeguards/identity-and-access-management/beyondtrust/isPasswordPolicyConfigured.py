"""
Transformation: isPasswordPolicyConfigured
Vendor: BeyondTrust  |  Category: Identity & Access Management
Evaluates: Whether at least one password complexity/rotation policy (PasswordRule)
is defined in the BeyondTrust system via the PasswordRules endpoint.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isPasswordPolicyConfigured", "vendor": "BeyondTrust", "category": "Identity & Access Management"}
        }
    }


def evaluate(data):
    """True if at least one PasswordRule is defined in BeyondTrust."""
    try:
        if isinstance(data, list):
            rules = data
        elif isinstance(data, dict):
            rules = data.get("PasswordRules", data.get("items", data.get("results", [])))
            if not isinstance(rules, list):
                rules = []
        else:
            return {"isPasswordPolicyConfigured": None,
                    "error": "required fields missing from API response: PasswordRules"}

        count = len(rules)
        if count == 0:
            return {"isPasswordPolicyConfigured": False, "policyCount": 0,
                    "reason": "No password policies found"}

        # Find the strongest minimum length across all policies (explicit loop, no max())
        strongest_min = 0
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            min_len = rule.get("MinimumLength", 0)
            if isinstance(min_len, (int, float)):
                as_int = int(min_len)
                if as_int > strongest_min:
                    strongest_min = as_int

        return {"isPasswordPolicyConfigured": True, "policyCount": count,
                "strongestMinLength": strongest_min}
    except Exception as e:
        return {"isPasswordPolicyConfigured": False, "error": str(e)}


def transform(input):
    criteriaKey = "isPasswordPolicyConfigured"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if result_value:
            pass_reasons.append(criteriaKey + " check passed")
            for k, v in extra_fields.items():
                pass_reasons.append(k + ": " + str(v))
        else:
            fail_reasons.append(criteriaKey + " check failed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Define at least one password complexity policy (PasswordRule) in BeyondTrust Configuration > Password Policies.")
        return create_response(
            result={criteriaKey: result_value, **extra_fields}, validation=validation,
            pass_reasons=pass_reasons, fail_reasons=fail_reasons, recommendations=recommendations,
            input_summary={criteriaKey: result_value, **extra_fields})
    except Exception as e:
        return create_response(
            result={criteriaKey: False}, validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)], fail_reasons=["Transformation error: " + str(e)])
