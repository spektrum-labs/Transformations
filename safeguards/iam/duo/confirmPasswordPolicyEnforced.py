"""
Transformation: confirmPasswordPolicyEnforced
Vendor: Duo  |  Category: iam
Evaluates: Evaluate administrator password policy settings from /admin/v1/settings including
           minimum_password_length, password_requires_upper_alpha, password_requires_lower_alpha,
           password_requires_numeric, and password_requires_special fields to confirm a strong
           password policy is enforced.
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


def get_settings(data):
    if isinstance(data, dict):
        candidate = data.get("response", None)
        if isinstance(candidate, dict):
            return candidate
        return data
    return {}


def safe_int(value, default):
    try:
        return int(value)
    except Exception:
        return default


def evaluate(data):
    try:
        settings = get_settings(data)

        min_length = safe_int(settings.get("minimum_password_length", 0), 0)
        requires_upper = bool(settings.get("password_requires_upper_alpha", False))
        requires_lower = bool(settings.get("password_requires_lower_alpha", False))
        requires_numeric = bool(settings.get("password_requires_numeric", False))
        requires_special = bool(settings.get("password_requires_special", False))

        length_adequate = min_length >= 8
        all_complexity_required = requires_upper and requires_lower and requires_numeric and requires_special
        policy_enforced = length_adequate and all_complexity_required

        return {
            "confirmPasswordPolicyEnforced": policy_enforced,
            "minimumPasswordLength": min_length,
            "requiresUpperAlpha": requires_upper,
            "requiresLowerAlpha": requires_lower,
            "requiresNumeric": requires_numeric,
            "requiresSpecial": requires_special,
            "lengthAdequate": length_adequate,
            "allComplexityRequired": all_complexity_required
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

        min_length = extra_fields.get("minimumPasswordLength", 0)
        requires_upper = extra_fields.get("requiresUpperAlpha", False)
        requires_lower = extra_fields.get("requiresLowerAlpha", False)
        requires_numeric = extra_fields.get("requiresNumeric", False)
        requires_special = extra_fields.get("requiresSpecial", False)
        length_adequate = extra_fields.get("lengthAdequate", False)
        all_complexity = extra_fields.get("allComplexityRequired", False)

        if result_value:
            pass_reasons.append("A strong password policy is enforced for administrator accounts")
            pass_reasons.append("minimumPasswordLength: " + str(min_length) + " (>= 8 required)")
            pass_reasons.append("All complexity requirements are enabled: upper, lower, numeric, special")
        else:
            if not length_adequate:
                fail_reasons.append("minimum_password_length is " + str(min_length) + " — must be at least 8 characters")
                recommendations.append("Set minimum_password_length to at least 8 in Duo Admin Panel settings")
            if not all_complexity:
                missing = []
                if not requires_upper:
                    missing.append("password_requires_upper_alpha")
                if not requires_lower:
                    missing.append("password_requires_lower_alpha")
                if not requires_numeric:
                    missing.append("password_requires_numeric")
                if not requires_special:
                    missing.append("password_requires_special")
                fail_reasons.append("The following password complexity requirements are not enabled: " + ", ".join(missing))
                recommendations.append("Enable all password complexity requirements in Duo Admin Panel — upper case, lower case, numeric, and special characters should all be required")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])

        if min_length > 0 and min_length < 12:
            additional_findings.append("minimumPasswordLength is " + str(min_length) + " — NIST SP 800-63B recommends a minimum of 12 characters for privileged accounts")

        result_dict = {criteriaKey: result_value}
        for k in extra_fields:
            result_dict[k] = extra_fields[k]

        return create_response(
            result=result_dict,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                criteriaKey: result_value,
                "minimumPasswordLength": min_length,
                "lengthAdequate": length_adequate,
                "allComplexityRequired": all_complexity
            }
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
