"""
Transformation: confirmPasswordPolicyEnforced
Vendor: Duo  |  Category: IAM
Evaluates: Confirms that a password policy is enforced by examining account settings fields:
minimum_password_length, password_requires_upper_alpha, password_requires_lower_alpha,
password_requires_numeric, password_requires_special, and lockout_threshold.
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
    """
    Inspect the 'settings' key returned by getAccountSettings.
    A policy is considered enforced when a meaningful minimum password length is
    configured, at least one character-class requirement is active, and an
    account-lockout threshold is set.
    """
    try:
        settings = data.get("settings", {})
        if not settings:
            return {
                "confirmPasswordPolicyEnforced": False,
                "error": "No account settings found in response",
                "settingsFound": False
            }

        min_length = settings.get("minimum_password_length", 0)
        requires_upper = settings.get("password_requires_upper_alpha", False)
        requires_lower = settings.get("password_requires_lower_alpha", False)
        requires_numeric = settings.get("password_requires_numeric", False)
        requires_special = settings.get("password_requires_special", False)
        lockout_threshold = settings.get("lockout_threshold", 0)

        has_min_length = min_length >= 8
        has_complexity = requires_upper or requires_lower or requires_numeric or requires_special
        has_lockout = lockout_threshold > 0

        policy_enforced = has_min_length and has_complexity and has_lockout

        return {
            "confirmPasswordPolicyEnforced": policy_enforced,
            "minimumPasswordLength": min_length,
            "requiresUpperAlpha": requires_upper,
            "requiresLowerAlpha": requires_lower,
            "requiresNumeric": requires_numeric,
            "requiresSpecial": requires_special,
            "lockoutThreshold": lockout_threshold,
            "hasMinimumLength": has_min_length,
            "hasComplexity": has_complexity,
            "hasLockout": has_lockout,
            "settingsFound": True
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

        extra_fields = {}
        for k in eval_result:
            if k != criteriaKey and k != "error":
                extra_fields[k] = eval_result[k]

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        if result_value:
            pass_reasons.append("Password policy is enforced: minimum length, complexity, and lockout are all configured")
            additional_findings.append("Minimum password length: " + str(eval_result.get("minimumPasswordLength", 0)))
            additional_findings.append("Lockout threshold: " + str(eval_result.get("lockoutThreshold", 0)))
        else:
            if eval_result.get("error"):
                fail_reasons.append(eval_result["error"])
            else:
                if not eval_result.get("hasMinimumLength", False):
                    fail_reasons.append("Minimum password length is below 8 characters (current: " + str(eval_result.get("minimumPasswordLength", 0)) + ")")
                    recommendations.append("Set minimum_password_length to 8 or higher in Duo account settings")
                if not eval_result.get("hasComplexity", False):
                    fail_reasons.append("No character-class complexity requirements are enabled")
                    recommendations.append("Enable at least one of: password_requires_upper_alpha, password_requires_lower_alpha, password_requires_numeric, password_requires_special")
                if not eval_result.get("hasLockout", False):
                    fail_reasons.append("Account lockout threshold is not configured (lockout_threshold is 0)")
                    recommendations.append("Set lockout_threshold to a positive value in Duo account settings to limit brute-force attempts")

        result_dict = {}
        result_dict[criteriaKey] = result_value
        for k in extra_fields:
            result_dict[k] = extra_fields[k]

        summary_dict = {}
        summary_dict[criteriaKey] = result_value
        for k in extra_fields:
            summary_dict[k] = extra_fields[k]

        return create_response(
            result=result_dict,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary=summary_dict,
            additional_findings=additional_findings
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
