"""
Transformation: confirmPasswordPolicyEnforced
Vendor: Duo  |  Category: iam
Evaluates: Checks GET /admin/v1/settings to confirm a strong password policy is enforced.
Validates minimum_password_length >= 8, plus upper/lower/numeric/special character requirements.
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
                "transformationId": "confirmPasswordPolicyEnforced",
                "vendor": "Duo",
                "category": "iam"
            }
        }
    }


def truthy(val):
    if isinstance(val, bool):
        return val
    if isinstance(val, int):
        return val != 0
    if isinstance(val, str):
        return val.lower() in ("true", "1", "yes")
    return False


def evaluate(data):
    try:
        settings = data.get("settings", data) if isinstance(data, dict) else {}

        min_length = settings.get("minimum_password_length", 0)
        requires_upper = settings.get("password_requires_upper_alpha", False)
        requires_lower = settings.get("password_requires_lower_alpha", False)
        requires_numeric = settings.get("password_requires_numeric", False)
        requires_special = settings.get("password_requires_special", False)

        requires_upper = truthy(requires_upper)
        requires_lower = truthy(requires_lower)
        requires_numeric = truthy(requires_numeric)
        requires_special = truthy(requires_special)

        try:
            min_length_int = int(min_length)
        except Exception:
            min_length_int = 0

        length_ok = min_length_int >= 8
        complexity_count = 0
        if requires_upper:
            complexity_count = complexity_count + 1
        if requires_lower:
            complexity_count = complexity_count + 1
        if requires_numeric:
            complexity_count = complexity_count + 1
        if requires_special:
            complexity_count = complexity_count + 1

        is_enforced = length_ok and complexity_count >= 3

        return {
            "confirmPasswordPolicyEnforced": is_enforced,
            "minimumPasswordLength": min_length_int,
            "requiresUpperAlpha": requires_upper,
            "requiresLowerAlpha": requires_lower,
            "requiresNumeric": requires_numeric,
            "requiresSpecial": requires_special,
            "complexityRulesCount": complexity_count
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
        min_length = eval_result.get("minimumPasswordLength", 0)
        requires_upper = eval_result.get("requiresUpperAlpha", False)
        requires_lower = eval_result.get("requiresLowerAlpha", False)
        requires_numeric = eval_result.get("requiresNumeric", False)
        requires_special = eval_result.get("requiresSpecial", False)
        complexity_count = eval_result.get("complexityRulesCount", 0)

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        if result_value:
            pass_reasons.append("Password policy is enforced with sufficient strength requirements")
            pass_reasons.append("Minimum password length: " + str(min_length))
            pass_reasons.append("Complexity rules active: " + str(complexity_count) + "/4")
        else:
            if min_length < 8:
                fail_reasons.append("Minimum password length is " + str(min_length) + " (required: >= 8)")
                recommendations.append("Set minimum_password_length to at least 8 in Duo Admin Panel settings")
            if complexity_count < 3:
                fail_reasons.append("Only " + str(complexity_count) + " of 4 complexity rules are enabled (required: >= 3)")
                if not requires_upper:
                    recommendations.append("Enable password_requires_upper_alpha in Duo Admin Panel settings")
                if not requires_lower:
                    recommendations.append("Enable password_requires_lower_alpha in Duo Admin Panel settings")
                if not requires_numeric:
                    recommendations.append("Enable password_requires_numeric in Duo Admin Panel settings")
                if not requires_special:
                    recommendations.append("Enable password_requires_special in Duo Admin Panel settings")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            if not fail_reasons:
                fail_reasons.append("confirmPasswordPolicyEnforced check failed")

        result = {
            "confirmPasswordPolicyEnforced": result_value,
            "minimumPasswordLength": min_length,
            "requiresUpperAlpha": requires_upper,
            "requiresLowerAlpha": requires_lower,
            "requiresNumeric": requires_numeric,
            "requiresSpecial": requires_special,
            "complexityRulesCount": complexity_count
        }

        return create_response(
            result=result,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "minimumPasswordLength": min_length,
                "complexityRulesCount": complexity_count
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
