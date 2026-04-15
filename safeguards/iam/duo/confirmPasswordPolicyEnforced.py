"""
Transformation: confirmPasswordPolicyEnforced
Vendor: Duo  |  Category: iam
Evaluates: Confirm that password complexity and strength policies are enforced by inspecting
Duo account settings fields including minimum_password_length, password_requires_upper_alpha,
password_requires_lower_alpha, password_requires_numeric, and password_requires_special.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "confirmPasswordPolicyEnforced", "vendor": "Duo", "category": "iam"}
        }
    }


def safe_int(value):
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        cleaned = value.strip()
        if cleaned.isdigit():
            total = 0
            for ch in cleaned:
                total = total * 10 + (ord(ch) - ord("0"))
            return total
    return 0


def safe_bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        return value.lower() in ["true", "1", "yes"]
    return False


def evaluate(data):
    try:
        settings = {}
        if isinstance(data, dict):
            if "data" in data and isinstance(data.get("data"), dict):
                settings = data.get("data", {})
            else:
                settings = data

        min_length_raw = settings.get("minimum_password_length", 0)
        min_length = safe_int(min_length_raw)

        requires_upper = safe_bool(settings.get("password_requires_upper_alpha", False))
        requires_lower = safe_bool(settings.get("password_requires_lower_alpha", False))
        requires_numeric = safe_bool(settings.get("password_requires_numeric", False))
        requires_special = safe_bool(settings.get("password_requires_special", False))

        length_ok = min_length >= 8
        policy_enforced = length_ok and requires_upper and requires_lower and requires_numeric and requires_special

        return {
            "confirmPasswordPolicyEnforced": policy_enforced,
            "minimumPasswordLength": min_length,
            "minimumLengthMet": length_ok,
            "requiresUpperAlpha": requires_upper,
            "requiresLowerAlpha": requires_lower,
            "requiresNumeric": requires_numeric,
            "requiresSpecial": requires_special
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
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        if result_value:
            pass_reasons.append("Password policy is fully enforced across all required complexity dimensions")
            pass_reasons.append("Minimum password length: " + str(eval_result.get("minimumPasswordLength", 0)) + " characters (>= 8 required)")
            pass_reasons.append("Upper alpha, lower alpha, numeric, and special character requirements are all enabled")
        else:
            fail_reasons.append("One or more password policy requirements are not enforced in Duo settings")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            if not eval_result.get("minimumLengthMet", False):
                fail_reasons.append("Minimum password length (" + str(eval_result.get("minimumPasswordLength", 0)) + ") is below the required minimum of 8 characters")
                recommendations.append("Set minimum_password_length to at least 8 characters in Duo account settings")
            if not eval_result.get("requiresUpperAlpha", False):
                fail_reasons.append("Upper-case alpha character requirement is not enforced")
                recommendations.append("Enable password_requires_upper_alpha in Duo account settings")
            if not eval_result.get("requiresLowerAlpha", False):
                fail_reasons.append("Lower-case alpha character requirement is not enforced")
                recommendations.append("Enable password_requires_lower_alpha in Duo account settings")
            if not eval_result.get("requiresNumeric", False):
                fail_reasons.append("Numeric character requirement is not enforced")
                recommendations.append("Enable password_requires_numeric in Duo account settings")
            if not eval_result.get("requiresSpecial", False):
                fail_reasons.append("Special character requirement is not enforced")
                recommendations.append("Enable password_requires_special in Duo account settings")

        additional_findings.append("Minimum password length configured: " + str(eval_result.get("minimumPasswordLength", 0)))
        additional_findings.append("Requires upper alpha: " + str(eval_result.get("requiresUpperAlpha", False)))
        additional_findings.append("Requires lower alpha: " + str(eval_result.get("requiresLowerAlpha", False)))
        additional_findings.append("Requires numeric: " + str(eval_result.get("requiresNumeric", False)))
        additional_findings.append("Requires special character: " + str(eval_result.get("requiresSpecial", False)))

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={criteriaKey: result_value, **extra_fields}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
