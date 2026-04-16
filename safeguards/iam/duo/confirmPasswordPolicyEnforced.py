"""
Transformation: confirmPasswordPolicyEnforced
Vendor: Duo  |  Category: IAM
Evaluates: Validates that a password policy is configured and enforced in Duo account settings
via GET /admin/v1/settings. Checks password complexity fields including
password_requires_length, password_requires_upper, password_requires_lower,
password_requires_digit, and password_requires_special.
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
                "category": "IAM"
            }
        }
    }


def get_bool_flag(settings, key):
    """Return True if the setting key is truthy (bool True, int 1, or non-zero)."""
    val = settings.get(key, None)
    if val is None:
        return False
    if isinstance(val, bool):
        return val
    if isinstance(val, int):
        return val != 0
    if isinstance(val, str):
        return val.lower() in ("true", "1", "yes", "enabled")
    return False


def get_min_length(settings):
    """Return the configured minimum password length, or 0 if not set."""
    val = settings.get("password_requires_length", 0)
    try:
        return int(val)
    except Exception:
        return 0


def evaluate(data):
    """
    Core evaluation logic for confirmPasswordPolicyEnforced.
    Duo getSettings returnSpec surfaces the settings object under the 'response' key.
    After extract_input unwraps any dict wrapper, 'data' should be the settings dict.
    Password policy fields evaluated:
      - password_requires_length  (int, min length > 0)
      - password_requires_upper   (bool/int)
      - password_requires_lower   (bool/int)
      - password_requires_digit   (bool/int)
      - password_requires_special (bool/int)
    The criteria passes if at least 3 of the 5 complexity controls are enabled.
    """
    try:
        settings = {}
        if isinstance(data, dict):
            settings = data
        else:
            return {
                "confirmPasswordPolicyEnforced": False,
                "error": "Unexpected data format: expected settings dict, got " + str(type(data))
            }

        requires_length = get_min_length(settings)
        requires_upper = get_bool_flag(settings, "password_requires_upper")
        requires_lower = get_bool_flag(settings, "password_requires_lower")
        requires_digit = get_bool_flag(settings, "password_requires_digit")
        requires_special = get_bool_flag(settings, "password_requires_special")

        length_configured = requires_length > 0

        # Count how many complexity rules are active
        active_rules = 0
        if length_configured:
            active_rules = active_rules + 1
        if requires_upper:
            active_rules = active_rules + 1
        if requires_lower:
            active_rules = active_rules + 1
        if requires_digit:
            active_rules = active_rules + 1
        if requires_special:
            active_rules = active_rules + 1

        # Pass if at least 3 of 5 complexity requirements are enforced
        is_enforced = active_rules >= 3

        return {
            "confirmPasswordPolicyEnforced": is_enforced,
            "activeComplexityRules": active_rules,
            "totalComplexityRules": 5,
            "passwordMinLength": requires_length,
            "requiresUpper": requires_upper,
            "requiresLower": requires_lower,
            "requiresDigit": requires_digit,
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

        active_rules = eval_result.get("activeComplexityRules", 0)
        total_rules = eval_result.get("totalComplexityRules", 5)
        min_length = eval_result.get("passwordMinLength", 0)
        req_upper = eval_result.get("requiresUpper", False)
        req_lower = eval_result.get("requiresLower", False)
        req_digit = eval_result.get("requiresDigit", False)
        req_special = eval_result.get("requiresSpecial", False)

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        if result_value:
            pass_reasons.append("Password policy is enforced with " + str(active_rules) + " of " + str(total_rules) + " complexity rules active")
            if min_length > 0:
                pass_reasons.append("Minimum password length configured: " + str(min_length) + " characters")
            if req_upper:
                pass_reasons.append("Uppercase character requirement is enabled")
            if req_lower:
                pass_reasons.append("Lowercase character requirement is enabled")
            if req_digit:
                pass_reasons.append("Digit requirement is enabled")
            if req_special:
                pass_reasons.append("Special character requirement is enabled")
        else:
            if "error" in eval_result:
                fail_reasons.append("Evaluation error: " + eval_result["error"])
            else:
                fail_reasons.append("Password policy is insufficiently configured: only " + str(active_rules) + " of " + str(total_rules) + " complexity rules are active")
                if min_length == 0:
                    fail_reasons.append("No minimum password length is configured")
                if not req_upper:
                    recommendations.append("Enable password_requires_upper in Duo account settings")
                if not req_lower:
                    recommendations.append("Enable password_requires_lower in Duo account settings")
                if not req_digit:
                    recommendations.append("Enable password_requires_digit in Duo account settings")
                if not req_special:
                    recommendations.append("Enable password_requires_special in Duo account settings")
                if min_length == 0:
                    recommendations.append("Set a minimum password length (e.g. 12 or more characters) in Duo account settings")

        additional_findings.append("Active complexity rules: " + str(active_rules) + "/" + str(total_rules))

        return create_response(
            result={
                criteriaKey: result_value,
                "activeComplexityRules": active_rules,
                "totalComplexityRules": total_rules,
                "passwordMinLength": min_length,
                "requiresUpper": req_upper,
                "requiresLower": req_lower,
                "requiresDigit": req_digit,
                "requiresSpecial": req_special
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                criteriaKey: result_value,
                "activeComplexityRules": active_rules,
                "passwordMinLength": min_length
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
