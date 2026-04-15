"""
Transformation: confirmPasswordPolicyEnforced
Vendor: Duo  |  Category: IAM
Evaluates: Validates that a strong password policy is enforced within Duo account settings,
including minimum length, complexity requirements, and lockout thresholds.
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


def evaluate(data):
    """
    Duo Admin API /admin/v1/settings returns a dict with fields like:
      minimum_password_length       (int, recommended >= 8)
      password_requires_upper_case  (bool/int)
      password_requires_lower_case  (bool/int)
      password_requires_numeric     (bool/int)
      password_requires_special     (bool/int)
      lockout_threshold             (int, recommended > 0)
      lockout_expire_duration       (int, minutes, recommended > 0)

    Policy is enforced if all complexity flags are enabled,
    minimum length >= 8, lockout_threshold > 0, and lockout_expire_duration > 0.
    """
    criteriaKey = "confirmPasswordPolicyEnforced"
    try:
        settings = data
        if not isinstance(settings, dict):
            return {criteriaKey: False, "error": "Settings data is not a dict"}

        fail_reasons = []
        findings = {}

        # Minimum password length
        min_length = settings.get("minimum_password_length", 0)
        findings["minimumPasswordLength"] = min_length
        if min_length < 8:
            fail_reasons.append("Minimum password length is below 8 (current: " + str(min_length) + ")")

        # Complexity flags — Duo returns 1/0 or True/False
        requires_upper = settings.get("password_requires_upper_case", 0)
        requires_lower = settings.get("password_requires_lower_case", 0)
        requires_numeric = settings.get("password_requires_numeric", 0)
        requires_special = settings.get("password_requires_special", 0)

        findings["requiresUpperCase"] = bool(requires_upper)
        findings["requiresLowerCase"] = bool(requires_lower)
        findings["requiresNumeric"] = bool(requires_numeric)
        findings["requiresSpecialChar"] = bool(requires_special)

        if not requires_upper:
            fail_reasons.append("Uppercase character requirement is not enabled")
        if not requires_lower:
            fail_reasons.append("Lowercase character requirement is not enabled")
        if not requires_numeric:
            fail_reasons.append("Numeric character requirement is not enabled")
        if not requires_special:
            fail_reasons.append("Special character requirement is not enabled")

        # Lockout threshold
        lockout_threshold = settings.get("lockout_threshold", 0)
        findings["lockoutThreshold"] = lockout_threshold
        if lockout_threshold <= 0:
            fail_reasons.append("Lockout threshold is not configured (must be > 0)")

        # Lockout duration
        lockout_duration = settings.get("lockout_expire_duration", 0)
        findings["lockoutExpireDuration"] = lockout_duration
        if lockout_duration <= 0:
            fail_reasons.append("Lockout expire duration is not configured (must be > 0)")

        enforced = len(fail_reasons) == 0
        result = {criteriaKey: enforced}
        for k in findings:
            result[k] = findings[k]
        result["policyFailures"] = fail_reasons
        return result

    except Exception as e:
        return {criteriaKey: False, "error": str(e)}


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
        policy_failures = eval_result.get("policyFailures", [])

        extra_fields = {}
        skip_keys = [criteriaKey, "error", "policyFailures"]
        for k in eval_result:
            if k not in skip_keys:
                extra_fields[k] = eval_result[k]

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        if result_value:
            pass_reasons.append("Password policy is fully enforced: minimum length, complexity, and lockout settings are all configured")
            for k in extra_fields:
                additional_findings.append(k + ": " + str(extra_fields[k]))
        else:
            if "error" in eval_result:
                fail_reasons.append("Evaluation error: " + eval_result["error"])
            else:
                fail_reasons.append("Password policy is not fully enforced")
                for pf in policy_failures:
                    fail_reasons.append(pf)
            recommendations.append("Enable all password complexity requirements in Duo Admin Panel under Settings > Password Policy")
            recommendations.append("Set a lockout threshold of 5-10 failed attempts and configure a lockout duration")
            for k in extra_fields:
                additional_findings.append(k + ": " + str(extra_fields[k]))

        combined_result = {criteriaKey: result_value}
        for k in extra_fields:
            combined_result[k] = extra_fields[k]

        combined_summary = {criteriaKey: result_value}
        for k in extra_fields:
            combined_summary[k] = extra_fields[k]

        return create_response(
            result=combined_result,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary=combined_summary
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
