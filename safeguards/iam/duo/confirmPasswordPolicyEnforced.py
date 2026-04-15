"""
Transformation: confirmPasswordPolicyEnforced
Vendor: Duo  |  Category: iam
Evaluates: Validate that a password policy is configured and enforced for all users
           by inspecting the global settings returned from the Duo Admin API settings endpoint.
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


def coerce_bool(value):
    """Normalize various truthy representations to a Python bool."""
    if value in (True, 1, "1", "true", "True", "yes", "enabled"):
        return True
    return False


def coerce_int(value, default):
    """Safely coerce a value to int."""
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value)
        except Exception:
            return default
    return default


def evaluate(data):
    """Core evaluation logic for confirmPasswordPolicyEnforced."""
    try:
        if not isinstance(data, dict):
            return {
                "confirmPasswordPolicyEnforced": False,
                "error": "Settings data is not a valid object"
            }

        if data.get("stat") == "FAIL":
            msg = data.get("message", "Duo API returned FAIL status")
            return {"confirmPasswordPolicyEnforced": False, "error": msg}

        # getSettings returnSpec maps response -> data, so settings fields are at top level
        settings = data

        min_length = coerce_int(settings.get("minimum_password_length", 0), 0)
        requires_upper = coerce_bool(settings.get("password_requires_upper_alpha", False))
        requires_lower = coerce_bool(settings.get("password_requires_lower_alpha", False))
        requires_special = coerce_bool(settings.get("password_requires_special", False))
        requires_numeric = coerce_bool(settings.get("password_requires_numeric", False))

        complexity_count = 0
        if requires_upper:
            complexity_count = complexity_count + 1
        if requires_lower:
            complexity_count = complexity_count + 1
        if requires_special:
            complexity_count = complexity_count + 1
        if requires_numeric:
            complexity_count = complexity_count + 1

        meets_min_length = min_length >= 8
        has_complexity = complexity_count >= 1

        is_enforced = meets_min_length and has_complexity

        return {
            "confirmPasswordPolicyEnforced": is_enforced,
            "minimumPasswordLength": min_length,
            "requiresUpperAlpha": requires_upper,
            "requiresLowerAlpha": requires_lower,
            "requiresSpecialCharacter": requires_special,
            "requiresNumeric": requires_numeric,
            "complexityRequirementsEnabled": complexity_count,
            "meetsMinimumLength": meets_min_length,
            "hasComplexityRequirements": has_complexity
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
        additional_findings = []

        min_len = eval_result.get("minimumPasswordLength", 0)
        req_upper = eval_result.get("requiresUpperAlpha", False)
        req_lower = eval_result.get("requiresLowerAlpha", False)
        req_special = eval_result.get("requiresSpecialCharacter", False)
        req_numeric = eval_result.get("requiresNumeric", False)
        complexity = eval_result.get("complexityRequirementsEnabled", 0)
        meets_length = eval_result.get("meetsMinimumLength", False)
        has_complexity = eval_result.get("hasComplexityRequirements", False)

        if result_value:
            pass_reasons.append("Password policy is configured and enforced in Duo global settings")
            pass_reasons.append("Minimum password length: " + str(min_len) + " characters (minimum required: 8)")
            pass_reasons.append("Number of complexity requirements enabled: " + str(complexity))
        else:
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            if not meets_length:
                fail_reasons.append("Minimum password length is " + str(min_len) + " which is below the required threshold of 8")
                recommendations.append("Increase minimum_password_length to at least 8 in Duo Admin global settings")
            if not has_complexity:
                fail_reasons.append("No password complexity requirements are currently enabled")
                recommendations.append("Enable at least one complexity requirement (uppercase, lowercase, special character, or numeric) in Duo Admin global settings")

        if req_upper:
            additional_findings.append("Uppercase letters required: yes")
        else:
            additional_findings.append("Uppercase letters required: no")
        if req_lower:
            additional_findings.append("Lowercase letters required: yes")
        else:
            additional_findings.append("Lowercase letters required: no")
        if req_special:
            additional_findings.append("Special characters required: yes")
        else:
            additional_findings.append("Special characters required: no")
        if req_numeric:
            additional_findings.append("Numeric characters required: yes")
        else:
            additional_findings.append("Numeric characters required: no")

        result_dict = {criteriaKey: result_value}
        result_dict["minimumPasswordLength"] = min_len
        result_dict["requiresUpperAlpha"] = req_upper
        result_dict["requiresLowerAlpha"] = req_lower
        result_dict["requiresSpecialCharacter"] = req_special
        result_dict["requiresNumeric"] = req_numeric
        result_dict["complexityRequirementsEnabled"] = complexity

        return create_response(
            result=result_dict,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={criteriaKey: result_value, "minimumPasswordLength": min_len, "complexityCount": complexity}
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
