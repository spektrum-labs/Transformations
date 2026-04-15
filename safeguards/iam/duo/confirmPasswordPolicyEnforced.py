"""
Transformation: confirmPasswordPolicyEnforced
Vendor: Duo  |  Category: IAM
Evaluates: Validates that a password policy is enforced within Duo account settings.
Inspects minimum_password_length, password_requires_upper_alpha, password_requires_lower_alpha,
password_requires_numeric, and password_requires_special_char to confirm a strong password
policy is active.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "confirmPasswordPolicyEnforced", "vendor": "Duo", "category": "IAM"}
        }
    }


def evaluate(data):
    try:
        settings = {}
        if isinstance(data, dict):
            settings = data.get("settings", data)
        if not isinstance(settings, dict):
            settings = {}

        min_length_raw = settings.get("minimum_password_length", 0)
        try:
            min_length = int(min_length_raw)
        except Exception:
            min_length = 0

        requires_upper = bool(settings.get("password_requires_upper_alpha", False))
        requires_lower = bool(settings.get("password_requires_lower_alpha", False))
        requires_numeric = bool(settings.get("password_requires_numeric", False))
        requires_special = bool(settings.get("password_requires_special_char", False))

        length_ok = min_length >= 8

        complexity_count = 0
        if requires_upper:
            complexity_count = complexity_count + 1
        if requires_lower:
            complexity_count = complexity_count + 1
        if requires_numeric:
            complexity_count = complexity_count + 1
        if requires_special:
            complexity_count = complexity_count + 1

        policy_enforced = length_ok and complexity_count >= 3

        return {
            "confirmPasswordPolicyEnforced": policy_enforced,
            "minimumPasswordLength": min_length,
            "passwordLengthMeetsRequirement": length_ok,
            "requiresUpperAlpha": requires_upper,
            "requiresLowerAlpha": requires_lower,
            "requiresNumeric": requires_numeric,
            "requiresSpecialChar": requires_special,
            "complexityRulesMet": complexity_count,
            "complexityRulesTotal": 4
        }
    except Exception as e:
        return {"confirmPasswordPolicyEnforced": False, "error": str(e)}


def transform(input):
    criteriaKey = "confirmPasswordPolicyEnforced"
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
        if result_value:
            pass_reasons.append("Password policy enforced: minimum length of " + str(eval_result.get("minimumPasswordLength", 0)) + " characters")
            pass_reasons.append(str(eval_result.get("complexityRulesMet", 0)) + " of 4 complexity rules are active")
        else:
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            if not eval_result.get("passwordLengthMeetsRequirement", False):
                fail_reasons.append("Minimum password length is " + str(eval_result.get("minimumPasswordLength", 0)) + ", which is below the required 8 characters")
                recommendations.append("Set minimum_password_length to at least 8 in Duo account settings")
            complexity_met = eval_result.get("complexityRulesMet", 0)
            if complexity_met < 3:
                fail_reasons.append("Only " + str(complexity_met) + " of 4 complexity rules active; at least 3 required")
                if not eval_result.get("requiresUpperAlpha", False):
                    recommendations.append("Enable password_requires_upper_alpha in Duo account settings")
                if not eval_result.get("requiresLowerAlpha", False):
                    recommendations.append("Enable password_requires_lower_alpha in Duo account settings")
                if not eval_result.get("requiresNumeric", False):
                    recommendations.append("Enable password_requires_numeric in Duo account settings")
                if not eval_result.get("requiresSpecialChar", False):
                    recommendations.append("Enable password_requires_special_char in Duo account settings")
        return create_response(
            result=eval_result,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "minimumPasswordLength": eval_result.get("minimumPasswordLength", 0),
                "complexityRulesMet": eval_result.get("complexityRulesMet", 0),
                "complexityRulesTotal": 4
            }
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
