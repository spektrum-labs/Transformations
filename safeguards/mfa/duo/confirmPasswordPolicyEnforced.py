"""
Transformation: confirmPasswordPolicyEnforced
Vendor: Duo  |  Category: MFA
Evaluates: Validates that a password policy is enforced by inspecting Duo account
settings fields: minimum_password_length, password_requires_upper_alpha,
password_requires_lower_alpha, password_requires_numeric, password_requires_special,
and lockout_threshold.
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
                "category": "MFA"
            }
        }
    }


def evaluate(data):
    """
    Inspect Duo account settings for password policy fields.
    Passes when:
      - minimum_password_length >= 8
      - at least 2 of the 4 complexity flags are enabled
      - lockout_threshold > 0
    """
    try:
        if not isinstance(data, dict):
            return {
                "confirmPasswordPolicyEnforced": False,
                "error": "Account settings data is not a dict; received type: " + str(type(data))
            }

        min_length = data.get("minimum_password_length", 0)
        try:
            min_length = int(min_length)
        except Exception:
            min_length = 0

        requires_upper = data.get("password_requires_upper_alpha", False)
        requires_lower = data.get("password_requires_lower_alpha", False)
        requires_numeric = data.get("password_requires_numeric", False)
        requires_special = data.get("password_requires_special", False)

        lockout_threshold = data.get("lockout_threshold", 0)
        try:
            lockout_threshold = int(lockout_threshold)
        except Exception:
            lockout_threshold = 0

        # Normalise truthy values that may arrive as strings
        def is_true(val):
            if isinstance(val, bool):
                return val
            if isinstance(val, str):
                return val.lower() in ("true", "1", "yes")
            if isinstance(val, int):
                return val != 0
            return False

        upper_ok = is_true(requires_upper)
        lower_ok = is_true(requires_lower)
        numeric_ok = is_true(requires_numeric)
        special_ok = is_true(requires_special)

        complexity_count = 0
        if upper_ok:
            complexity_count = complexity_count + 1
        if lower_ok:
            complexity_count = complexity_count + 1
        if numeric_ok:
            complexity_count = complexity_count + 1
        if special_ok:
            complexity_count = complexity_count + 1

        length_ok = min_length >= 8
        complexity_ok = complexity_count >= 2
        lockout_ok = lockout_threshold > 0

        policy_enforced = length_ok and complexity_ok and lockout_ok

        return {
            "confirmPasswordPolicyEnforced": policy_enforced,
            "minimumPasswordLength": min_length,
            "passwordRequiresUpperAlpha": upper_ok,
            "passwordRequiresLowerAlpha": lower_ok,
            "passwordRequiresNumeric": numeric_ok,
            "passwordRequiresSpecial": special_ok,
            "lockoutThreshold": lockout_threshold,
            "complexityRequirementsMet": complexity_ok,
            "complexityFlagsEnabled": complexity_count,
            "minimumLengthMet": length_ok,
            "lockoutConfigured": lockout_ok
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

        if "error" in eval_result:
            fail_reasons.append("Evaluation error: " + eval_result["error"])
            recommendations.append("Ensure getAccountSettings returns a valid Duo settings object")
        else:
            min_len = eval_result.get("minimumPasswordLength", 0)
            lockout = eval_result.get("lockoutThreshold", 0)
            complexity = eval_result.get("complexityFlagsEnabled", 0)

            if eval_result.get("minimumLengthMet"):
                pass_reasons.append("Minimum password length is " + str(min_len) + " characters (>= 8)")
            else:
                fail_reasons.append("Minimum password length is " + str(min_len) + " (requires >= 8)")
                recommendations.append("Increase minimum_password_length to at least 8 in Duo account settings")

            if eval_result.get("complexityRequirementsMet"):
                pass_reasons.append(str(complexity) + " of 4 complexity flags are enabled")
            else:
                fail_reasons.append("Only " + str(complexity) + " of 4 complexity flags enabled (requires >= 2)")
                recommendations.append(
                    "Enable at least 2 of: password_requires_upper_alpha, password_requires_lower_alpha, "
                    "password_requires_numeric, password_requires_special"
                )

            if eval_result.get("lockoutConfigured"):
                pass_reasons.append("Account lockout threshold is configured (" + str(lockout) + " attempts)")
            else:
                fail_reasons.append("Account lockout threshold is not configured (lockout_threshold = 0)")
                recommendations.append("Set lockout_threshold to a positive value in Duo account settings")

            if result_value:
                pass_reasons.append("Password policy is fully enforced in Duo account settings")
            else:
                additional_findings.append(
                    "One or more password policy requirements are not met. "
                    "Review Duo Admin Panel > Settings > Password Policy."
                )

        full_result = {criteriaKey: result_value}
        for k in extra_fields:
            full_result[k] = extra_fields[k]

        return create_response(
            result=full_result,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "minimumPasswordLength": eval_result.get("minimumPasswordLength", 0),
                "complexityFlagsEnabled": eval_result.get("complexityFlagsEnabled", 0),
                "lockoutThreshold": eval_result.get("lockoutThreshold", 0)
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
