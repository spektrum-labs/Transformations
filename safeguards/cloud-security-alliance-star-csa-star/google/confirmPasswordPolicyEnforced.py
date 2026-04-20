"""
Transformation: confirmPasswordPolicyEnforced
Vendor: Google  |  Category: cloud-security-alliance-star-csa-star
Evaluates: Examines Cloud Identity Policy API response for entries with
setting.type matching password or authentication policy types. Confirms that
password strength enforcement (enforceStrongPassword), minimum length, and
expiration settings are configured and active.
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
                "vendor": "Google",
                "category": "cloud-security-alliance-star-csa-star"
            }
        }
    }


def is_password_policy_type(setting_type):
    """
    Returns True if the setting type string relates to password policy.
    Cloud Identity API setting types include values like:
      - cloudidentity.googleapis.com/policies.security.password
      - PASSWORD
      - security.password
    Checks for known substrings in a case-insensitive manner by lowercasing.
    """
    if not setting_type:
        return False
    lower_type = ""
    for ch in setting_type:
        if ch >= "A" and ch <= "Z":
            lower_type = lower_type + chr(ord(ch) + 32)
        else:
            lower_type = lower_type + ch
    return "password" in lower_type


def evaluate(data):
    """
    Scans Cloud Identity policies array for password-related policy entries.
    Checks for enforceStrongPassword, minimumLength, and expirationDuration
    within each matching policy's setting.value fields.
    """
    try:
        policies = data.get("policies", [])
        if not isinstance(policies, list):
            policies = []

        total_policies = len(policies)
        password_policies_found = []
        strong_password_enforced = False
        min_length_set = False
        expiration_set = False
        min_length_value = 0
        expiration_value = ""

        for policy in policies:
            setting = policy.get("setting", {})
            if not isinstance(setting, dict):
                setting = {}

            setting_type = setting.get("type", "")
            if not is_password_policy_type(setting_type):
                continue

            policy_name = policy.get("name", "")
            password_policies_found.append(policy_name)

            setting_value = setting.get("value", {})
            if not isinstance(setting_value, dict):
                setting_value = {}

            strong_val = setting_value.get("enforceStrongPassword", None)
            if strong_val is True or strong_val == "true" or strong_val == "TRUE":
                strong_password_enforced = True

            min_len = setting_value.get("minimumLength", None)
            if min_len is not None:
                try:
                    min_len_int = int(min_len)
                    if min_len_int > 0:
                        min_length_set = True
                        min_length_value = min_len_int
                except Exception:
                    pass

            expiry = setting_value.get("passwordExpirationDuration", None)
            if expiry is None:
                expiry = setting_value.get("expirationDuration", None)
            if expiry is not None and str(expiry) != "" and str(expiry) != "0" and str(expiry) != "0s":
                expiration_set = True
                expiration_value = str(expiry)

        policy_enforced = len(password_policies_found) > 0 and strong_password_enforced

        return {
            "confirmPasswordPolicyEnforced": policy_enforced,
            "passwordPoliciesFound": len(password_policies_found),
            "strongPasswordEnforced": strong_password_enforced,
            "minimumLengthSet": min_length_set,
            "minimumLengthValue": min_length_value,
            "expirationSet": expiration_set,
            "expirationValue": expiration_value,
            "totalPoliciesScanned": total_policies,
            "passwordPolicyNames": password_policies_found
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

        policies_found = eval_result.get("passwordPoliciesFound", 0)
        strong_enforced = eval_result.get("strongPasswordEnforced", False)
        min_length_set = eval_result.get("minimumLengthSet", False)
        min_length_val = eval_result.get("minimumLengthValue", 0)
        expiry_set = eval_result.get("expirationSet", False)
        expiry_val = eval_result.get("expirationValue", "")
        total_scanned = eval_result.get("totalPoliciesScanned", 0)

        if result_value:
            pass_reasons.append("Password policy is enforced — " + str(policies_found) + " password policy record(s) found with strong password enforcement active")
            if min_length_set:
                pass_reasons.append("Minimum password length configured: " + str(min_length_val) + " characters")
            if expiry_set:
                pass_reasons.append("Password expiration is configured: " + str(expiry_val))
        else:
            if policies_found == 0 and total_scanned == 0:
                fail_reasons.append("No policies returned by Cloud Identity API — unable to assess password policy")
                recommendations.append("Ensure the OAuth token has cloud-identity.policies.readonly scope and the policies API is accessible")
            elif policies_found == 0:
                fail_reasons.append("No password-related policies found among " + str(total_scanned) + " total policies")
                recommendations.append("Configure a password policy in the Google Admin Console under Security > Password management")
            else:
                fail_reasons.append("Password policy found but strong password enforcement is not enabled")
                recommendations.append("Enable Enforce strong password in the Google Admin Console under Security > Password management")

            if not min_length_set:
                additional_findings.append("Minimum password length is not explicitly configured")
                recommendations.append("Set a minimum password length of at least 8 characters in the Admin Console")
            if not expiry_set:
                additional_findings.append("Password expiration is not configured or set to never expire")

            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])

        if min_length_set:
            additional_findings.append("Minimum password length: " + str(min_length_val))
        if expiry_set:
            additional_findings.append("Password expiration duration: " + str(expiry_val))

        combined_result = {criteriaKey: result_value}
        for k in extra_fields:
            combined_result[k] = extra_fields[k]

        return create_response(
            result=combined_result,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "totalPoliciesScanned": total_scanned,
                "passwordPoliciesFound": policies_found
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
