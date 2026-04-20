"""
Transformation: confirmPasswordPolicyEnforced
Vendor: Multifactor Authentication  |  Category: iam
Evaluates: Inspect Duo account settings to verify that password policy controls are
           enabled, including minimum_password_length is set to a secure value (>= 8)
           and complexity requirements password_requires_special_char and
           password_requires_upper_lower are both enforced.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for loop_idx in range(3):
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
                "vendor": "Multifactor Authentication",
                "category": "iam"
            }
        }
    }


def evaluate(data):
    try:
        settings = data
        if "response" in data and isinstance(data.get("response"), dict):
            settings = data["response"]

        min_length = settings.get("minimum_password_length", 0)
        requires_special = settings.get("password_requires_special_char", False)
        requires_upper_lower = settings.get("password_requires_upper_lower", False)

        min_length_int = 0
        if min_length:
            min_length_int = int(min_length)

        min_length_ok = min_length_int >= 8
        is_enforced = min_length_ok and bool(requires_special) and bool(requires_upper_lower)

        return {
            "confirmPasswordPolicyEnforced": is_enforced,
            "minimumPasswordLength": min_length_int,
            "requiresSpecialChar": bool(requires_special),
            "requiresUpperLower": bool(requires_upper_lower),
            "minimumPasswordLengthMet": min_length_ok,
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
                fail_reasons=["Input validation failed"])
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []
        if result_value:
            pass_reasons.append("Password policy is fully enforced with secure settings")
            pass_reasons.append("Minimum password length: " + str(eval_result.get("minimumPasswordLength", 0)))
            pass_reasons.append("Special character requirement enabled: " + str(eval_result.get("requiresSpecialChar", False)))
            pass_reasons.append("Upper/lower case requirement enabled: " + str(eval_result.get("requiresUpperLower", False)))
        else:
            fail_reasons.append("Password policy is not fully enforced")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            if not eval_result.get("minimumPasswordLengthMet", False):
                fail_reasons.append(
                    "Minimum password length is below the required threshold of 8 characters (current: "
                    + str(eval_result.get("minimumPasswordLength", 0)) + ")")
                recommendations.append("Set minimum_password_length to at least 8 in Duo account settings")
            if not eval_result.get("requiresSpecialChar", False):
                fail_reasons.append("Special character requirement is not enabled")
                recommendations.append("Enable password_requires_special_char in Duo account settings")
            if not eval_result.get("requiresUpperLower", False):
                fail_reasons.append("Upper/lower case character requirement is not enabled")
                recommendations.append("Enable password_requires_upper_lower in Duo account settings")
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "minimumPasswordLength": eval_result.get("minimumPasswordLength", 0),
                "requiresSpecialChar": eval_result.get("requiresSpecialChar", False),
                "requiresUpperLower": eval_result.get("requiresUpperLower", False)
            })
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)])
