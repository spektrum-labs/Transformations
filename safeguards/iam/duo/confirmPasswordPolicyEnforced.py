"""
Transformation: confirmPasswordPolicyEnforced
Vendor: Duo  |  Category: iam
Evaluates: Validates that a strong password policy is enforced by inspecting the settings
           response from GET /admin/v1/settings. Checks that minimum_password_length >= 12
           and that password_requires_upper_lower, password_requires_special, and
           password_requires_numeric are all true.
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


def parse_int_safe(value):
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except Exception:
            return 0
    return 0


def evaluate(data):
    try:
        settings = data.get("settings", {})
        if not settings:
            settings = data

        failures = []
        findings = []

        min_length = parse_int_safe(settings.get("minimum_password_length", 0))
        requires_upper_lower = settings.get("password_requires_upper_lower", False)
        requires_special = settings.get("password_requires_special", False)
        requires_numeric = settings.get("password_requires_numeric", False)

        if min_length < 12:
            failures.append("minimum_password_length is " + str(min_length) + " (required: >= 12)")
        else:
            findings.append("minimum_password_length is " + str(min_length) + " (compliant)")

        if not requires_upper_lower:
            failures.append("password_requires_upper_lower is not enabled")
        else:
            findings.append("password_requires_upper_lower is enabled")

        if not requires_special:
            failures.append("password_requires_special is not enabled")
        else:
            findings.append("password_requires_special is enabled")

        if not requires_numeric:
            failures.append("password_requires_numeric is not enabled")
        else:
            findings.append("password_requires_numeric is enabled")

        is_enforced = len(failures) == 0

        return {
            "confirmPasswordPolicyEnforced": is_enforced,
            "minimumPasswordLength": min_length,
            "requiresUpperLower": requires_upper_lower,
            "requiresSpecial": requires_special,
            "requiresNumeric": requires_numeric,
            "policyFailures": failures,
            "policyFindings": findings
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
        additional_findings = eval_result.get("policyFindings", [])

        if result_value:
            pass_reasons.append("Password policy is fully enforced with all required complexity rules")
            pass_reasons.append("Minimum password length: " + str(eval_result.get("minimumPasswordLength", 0)))
            pass_reasons.append("Upper/lower, special character, and numeric requirements are all active")
        else:
            fail_reasons.append("Password policy is not fully enforced")
            for failure in eval_result.get("policyFailures", []):
                fail_reasons.append(failure)
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Set minimum_password_length to at least 12 in Duo Admin Panel under Settings")
            recommendations.append("Enable password_requires_upper_lower, password_requires_special, and password_requires_numeric")

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "settingsPresent": bool(data.get("settings")),
                criteriaKey: result_value
            },
            additional_findings=additional_findings
        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
