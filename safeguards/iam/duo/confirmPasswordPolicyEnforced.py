"""
Transformation: confirmPasswordPolicyEnforced
Vendor: Duo  |  Category: iam
Evaluates: Confirms that a password policy is enforced by checking minimum_password_length (>= 8),
password_requires_upper_alpha, password_requires_lower_alpha, password_requires_numeric,
and password_requires_special from /admin/v1/settings.
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
                "category": "iam"
            }
        }
    }


def bool_val(raw):
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, int):
        return raw != 0
    if isinstance(raw, str):
        return raw.lower() in ("true", "1", "yes")
    return False


def evaluate(data):
    try:
        min_length_raw = data.get("minimum_password_length", 0)
        min_length = 0
        if isinstance(min_length_raw, int):
            min_length = min_length_raw
        elif isinstance(min_length_raw, str):
            if min_length_raw.isdigit():
                min_length = int(min_length_raw)

        requires_upper = bool_val(data.get("password_requires_upper_alpha", False))
        requires_lower = bool_val(data.get("password_requires_lower_alpha", False))
        requires_numeric = bool_val(data.get("password_requires_numeric", False))
        requires_special = bool_val(data.get("password_requires_special", False))

        length_ok = min_length >= 8
        all_complexity_met = requires_upper and requires_lower and requires_numeric and requires_special
        policy_enforced = length_ok and all_complexity_met

        failing_checks = []
        if not length_ok:
            failing_checks.append("minimum_password_length is " + str(min_length) + " (required >= 8)")
        if not requires_upper:
            failing_checks.append("password_requires_upper_alpha is not enabled")
        if not requires_lower:
            failing_checks.append("password_requires_lower_alpha is not enabled")
        if not requires_numeric:
            failing_checks.append("password_requires_numeric is not enabled")
        if not requires_special:
            failing_checks.append("password_requires_special is not enabled")

        return {
            "confirmPasswordPolicyEnforced": policy_enforced,
            "minimumPasswordLength": min_length,
            "requiresUpperAlpha": requires_upper,
            "requiresLowerAlpha": requires_lower,
            "requiresNumeric": requires_numeric,
            "requiresSpecial": requires_special,
            "lengthPolicyMet": length_ok,
            "complexityPolicyMet": all_complexity_met,
            "failingChecks": failing_checks
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
            pass_reasons.append("Password policy is fully enforced: minimum length >= 8 and all complexity requirements are enabled")
            pass_reasons.append("Minimum password length: " + str(extra_fields.get("minimumPasswordLength", 0)))
        else:
            fail_reasons.append("Password policy is not fully enforced")
            failing_checks = extra_fields.get("failingChecks", [])
            for check in failing_checks:
                fail_reasons.append(check)
            recommendations.append("Configure Duo Admin API settings to enforce minimum_password_length >= 8 and enable all password complexity requirements")
            if not extra_fields.get("lengthPolicyMet", False):
                additional_findings.append("Current minimum_password_length: " + str(extra_fields.get("minimumPasswordLength", 0)))
            if not extra_fields.get("complexityPolicyMet", False):
                additional_findings.append("One or more complexity requirements (upper, lower, numeric, special) are disabled")

        result_dict = {criteriaKey: result_value}
        for k in extra_fields:
            result_dict[k] = extra_fields[k]

        summary_dict = {criteriaKey: result_value}
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
